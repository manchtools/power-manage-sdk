package terminal

// DefaultUIDOffset is the default UID offset between a regular Linux user
// and its dedicated TTY user. With the default of 100000, regular UIDs in
// the range 1000–99999 map to TTY UIDs in 101000–199999, leaving no overlap.
const DefaultUIDOffset = 100000

// TTYUsernamePrefix is prepended to a Linux username to derive the TTY
// username (e.g. "pdotterer" -> "pm-tty-pdotterer").
const TTYUsernamePrefix = "pm-tty-"

// TTYUsername returns the TTY user name for a given Linux username.
// The TTY user is a dedicated `pm-tty-<username>` account used to run
// remote terminal sessions, separate from the user's own Linux account.
func TTYUsername(linuxUsername string) string {
	return TTYUsernamePrefix + linuxUsername
}

// TTYUID returns the TTY UID for a given Linux UID using the supplied
// offset. Pass DefaultUIDOffset to use the default mapping.
func TTYUID(linuxUID, offset int) int {
	return linuxUID + offset
}

// OriginalUID reverses the TTY UID mapping, returning the original Linux
// UID that produced the given TTY UID with the supplied offset.
func OriginalUID(ttyUID, offset int) int {
	return ttyUID - offset
}
