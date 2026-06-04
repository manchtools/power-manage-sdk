package remote

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// fetchPrefix is the prefix-sync branch of s3Source.Fetch. Triggered
// when cfg.Key has a trailing "/" (the convention NewS3 documents).
//
// Flow:
//  1. validateDestination — same path safety as every other source.
//  2. listObjectsV2 — paginate the bucket under the key prefix to get
//     the canonical (key, ETag) set the call should mirror.
//  3. list-hash drift compare against the cached revision; if it
//     matches, return Changed=false without any object GETs.
//  4. for each object: GET if missing locally OR local ETag differs;
//     write atomically through streamToTmp + rename.
//  5. when cfg.Prune is true: pruneTo with the source-relative paths.
//
// Concurrency: this v1 fetches sequentially. A future iteration could
// parallelise the per-object GETs; defer that until benchmarks
// motivate it.
func (s *s3Source) fetchPrefix(ctx context.Context, dest string) (Result, error) {
	if err := validateDestination(dest); err != nil {
		return Result{}, err
	}

	objects, err := s.listObjects(ctx)
	if err != nil {
		return Result{}, err
	}
	listHash := hashListing(objects)

	s.mu.Lock()
	cachedRevision := s.revision
	s.mu.Unlock()

	if cachedRevision == listHash {
		return Result{Changed: false, Revision: listHash}, nil
	}

	if err := os.MkdirAll(dest, 0o755); err != nil {
		return Result{}, fmt.Errorf("mkdir %s: %w", dest, err)
	}

	var (
		bytesWritten int64
		filesTouched int
	)
	maxBytes := int64(defaultHTTPMaxBytes)
	relPaths := make(map[string]struct{}, len(objects))

	for _, obj := range objects {
		rel, err := relPathForKey(s.cfg.Key, obj.Key)
		if err != nil {
			return Result{}, err
		}
		relPaths[rel] = struct{}{}

		outPath := filepath.Join(dest, filepath.FromSlash(rel))
		// Defense-in-depth: a malformed object key (with .. or
		// embedded NUL) must not write outside dest.
		if err := assertWithinDest(dest, outPath); err != nil {
			return Result{}, err
		}

		body, etag, err := s.openSingleObject(ctx, obj.Key)
		if err != nil {
			return Result{}, err
		}
		written, _, err := streamObjectToFile(body, outPath, maxBytes)
		body.Close()
		if err != nil {
			return Result{}, err
		}
		_ = etag // available for per-object drift in a future iteration
		bytesWritten += written
		filesTouched++
	}

	if s.cfg.Prune {
		if err := pruneTo(dest, relPaths); err != nil {
			return Result{}, fmt.Errorf("prune %s: %w", dest, err)
		}
	}

	if err := applyMode(ctx, dest, s.cfg.Mode, s.cfg.Owner, s.cfg.Group); err != nil {
		return Result{}, err
	}

	s.mu.Lock()
	s.revision = listHash
	s.mu.Unlock()
	RecordDest(dest)

	return Result{
		Changed:      true,
		BytesWritten: bytesWritten,
		FilesTouched: filesTouched,
		Revision:     listHash,
	}, nil
}

// s3Object is the parsed projection of one ListObjectsV2 entry. ETag
// is the raw header form (quoted hex); the caller doesn't compare it
// against anything that cares about the quoting.
type s3Object struct {
	Key  string
	ETag string
	Size int64
}

// maxPrefixObjects caps the total objects a single prefix-sync will
// enumerate. Defeats accidental "mirror an entire petabyte bucket"
// configurations that would otherwise let listObjects accumulate a
// few million entries in memory before the Fetch even gets to its
// first GET. 10 000 lines up with one AWS list page × ~10 — large
// enough for any docs / configs / asset use case this primitive
// targets, small enough to surface "you misconfigured the prefix"
// clearly.
const maxPrefixObjects = 10000

// listObjects paginates ?list-type=2 until IsTruncated=false. Each
// page contributes its Contents to the accumulated set, and the
// NextContinuationToken from one page becomes the
// ContinuationToken query of the next. Exceeding maxPrefixObjects
// surfaces as ErrInvalidConfig so the operator can narrow the prefix.
func (s *s3Source) listObjects(ctx context.Context) ([]s3Object, error) {
	endpoint, _ := url.Parse(s.objectURL) // already validated in NewS3
	bucketURL := *endpoint
	// Listing happens at the bucket root, NOT the prefix path.
	parts := strings.SplitN(strings.TrimPrefix(endpoint.Path, "/"), "/", 2)
	if len(parts) == 0 {
		return nil, fmt.Errorf("%w: cannot derive bucket from %s", ErrInvalidConfig, s.objectURL)
	}
	bucketURL.Path = "/" + parts[0]

	var all []s3Object
	var token string
	for {
		q := url.Values{}
		q.Set("list-type", "2")
		q.Set("prefix", s.cfg.Key)
		if token != "" {
			q.Set("continuation-token", token)
		}
		bucketURL.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, bucketURL.String(), nil)
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", bucketURL.String(), err)
		}
		resp, err := s.client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("list %s: %w", bucketURL.String(), err)
		}
		switch {
		case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized:
			resp.Body.Close()
			return nil, fmt.Errorf("%w: anonymous list on %s returned %d (bucket policy may need adjustment)", ErrInvalidConfig, bucketURL.String(), resp.StatusCode)
		case resp.StatusCode < 200 || resp.StatusCode >= 300:
			resp.Body.Close()
			return nil, fmt.Errorf("list %s: status %d", bucketURL.String(), resp.StatusCode)
		}

		var parsed listV2Response
		if err := xml.NewDecoder(resp.Body).Decode(&parsed); err != nil {
			resp.Body.Close()
			return nil, fmt.Errorf("decode list %s: %w", bucketURL.String(), err)
		}
		resp.Body.Close()
		for _, e := range parsed.Contents {
			all = append(all, s3Object{Key: e.Key, ETag: e.ETag, Size: e.Size})
			if len(all) > maxPrefixObjects {
				return nil, fmt.Errorf("%w: prefix %q under %s/%s contains more than %d objects; narrow the prefix or paginate the source", ErrInvalidConfig, s.cfg.Key, s.cfg.Endpoint, parts[0], maxPrefixObjects)
			}
		}
		if !parsed.IsTruncated || parsed.NextContinuationToken == "" {
			break
		}
		token = parsed.NextContinuationToken
	}
	return all, nil
}

type listV2Response struct {
	XMLName               xml.Name `xml:"ListBucketResult"`
	IsTruncated           bool     `xml:"IsTruncated"`
	NextContinuationToken string   `xml:"NextContinuationToken"`
	Contents              []struct {
		Key  string `xml:"Key"`
		ETag string `xml:"ETag"`
		Size int64  `xml:"Size"`
	} `xml:"Contents"`
}

// hashListing returns a canonical sha256 of the listing, used as the
// prefix-sync drift token. Keys are sorted lexically and joined with
// ETags so two identical listings always produce the same hash, even
// if the server delivered them in a different order across paginated
// responses.
func hashListing(objs []s3Object) string {
	sort.Slice(objs, func(i, j int) bool { return objs[i].Key < objs[j].Key })
	h := sha256.New()
	for _, o := range objs {
		_, _ = io.WriteString(h, o.Key)
		_, _ = io.WriteString(h, "\x00")
		_, _ = io.WriteString(h, o.ETag)
		_, _ = io.WriteString(h, "\x00")
	}
	return hex.EncodeToString(h.Sum(nil))
}

// openSingleObject is openObject restricted to the v1 anonymous-GET
// surface, parameterised by the full key (rather than the cfg.Key the
// prefix-sync path can't use).
func (s *s3Source) openSingleObject(ctx context.Context, key string) (io.ReadCloser, string, error) {
	endpoint, _ := url.Parse(s.objectURL)
	bucketAndKey := *endpoint
	parts := strings.SplitN(strings.TrimPrefix(endpoint.Path, "/"), "/", 2)
	bucket := parts[0]
	bucketAndKey.Path = "/" + bucket + "/" + key

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, bucketAndKey.String(), nil)
	if err != nil {
		return nil, "", fmt.Errorf("GET %s: %w", bucketAndKey.String(), err)
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("GET %s: %w", bucketAndKey.String(), err)
	}
	if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized {
		resp.Body.Close()
		return nil, "", fmt.Errorf("%w: anonymous GET on %s returned %d", ErrInvalidConfig, bucketAndKey.String(), resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		return nil, "", fmt.Errorf("GET %s: status %d", bucketAndKey.String(), resp.StatusCode)
	}
	return resp.Body, resp.Header.Get("ETag"), nil
}

// streamObjectToFile is streamToTmp + rename in one helper, tailored
// for the prefix-sync case where the dest path is per-object and we
// don't need the tmp path back.
func streamObjectToFile(body io.Reader, outPath string, maxBytes int64) (int64, []byte, error) {
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return 0, nil, fmt.Errorf("mkdir %s: %w", filepath.Dir(outPath), err)
	}
	tmp, written, sum, err := streamToTmp(outPath, body, maxBytes)
	if err != nil {
		return 0, nil, err
	}
	if err := os.Rename(tmp, outPath); err != nil {
		_ = os.Remove(tmp)
		return 0, nil, fmt.Errorf("rename to %s: %w", outPath, err)
	}
	return written, sum, nil
}

// relPathForKey maps an S3 key under a prefix to its dest-relative
// path. Refuses keys that don't begin with the prefix (defensive: a
// server bug or proxy quirk could otherwise plant files outside the
// expected subtree) and any key containing traversal segments.
func relPathForKey(prefix, key string) (string, error) {
	if !strings.HasPrefix(key, prefix) {
		return "", fmt.Errorf("%w: object key %q does not begin with prefix %q", ErrInvalidConfig, key, prefix)
	}
	rel := strings.TrimPrefix(key, prefix)
	if rel == "" {
		return "", fmt.Errorf("%w: object key %q matches the prefix exactly (cannot map to file)", ErrInvalidConfig, key)
	}
	if strings.ContainsRune(rel, 0) {
		return "", fmt.Errorf("%w: object key %q contains NUL", ErrUnsafeDestination, key)
	}
	for _, comp := range strings.Split(rel, "/") {
		if comp == ".." {
			return "", fmt.Errorf("%w: object key %q contains ..", ErrUnsafeDestination, key)
		}
	}
	return rel, nil
}

// assertWithinDest is the post-join safety check — equivalent to the
// archive extractor's last-step abs-path compare, applied here to
// catch any path that normalises outside dest after platform-specific
// separator handling.
func assertWithinDest(dest, full string) error {
	destAbs, err := filepath.Abs(dest)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnsafeDestination, err)
	}
	fullAbs, err := filepath.Abs(full)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnsafeDestination, err)
	}
	if !strings.HasPrefix(fullAbs, destAbs+string(filepath.Separator)) && fullAbs != destAbs {
		return fmt.Errorf("%w: %s resolves outside %s", ErrUnsafeDestination, full, dest)
	}
	return nil
}

// init wires the prefix-sync dispatcher into s3Source.Fetch.
func init() {
	s3PrefixDispatch = func(ctx context.Context, s *s3Source, dest string) (Result, error) {
		return s.fetchPrefix(ctx, dest)
	}
}

// s3PrefixDispatch is the seam s3.go's Fetch calls into for the
// prefix-sync branch.
var s3PrefixDispatch func(ctx context.Context, s *s3Source, dest string) (Result, error)

// errPrefixSyncUnimplemented — sentinel returned when the prefix
// dispatcher hasn't been wired up yet (a build-tag scenario nothing
// in production triggers; keeps the error message clear if it
// somehow does).
var errPrefixSyncUnimplemented = errors.New("remote: S3 prefix sync dispatcher not registered")
