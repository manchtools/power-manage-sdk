import { AgentMessage, RegisterRequest, RegisterResponse, ServerMessage } from "./agent_pb.js";
import { MethodKind } from "@bufbuild/protobuf";
/**
 * @generated from service powermanage.v1.AgentService
 */
export declare const AgentService: {
    readonly typeName: "powermanage.v1.AgentService";
    readonly methods: {
        /**
         * Single bidirectional stream for all agent-server communication
         *
         * @generated from rpc powermanage.v1.AgentService.AgentStream
         */
        readonly agentStream: {
            readonly name: "AgentStream";
            readonly I: typeof AgentMessage;
            readonly O: typeof ServerMessage;
            readonly kind: MethodKind.BiDiStreaming;
        };
        /**
         * Registration endpoint (unary, used before stream is established)
         *
         * @generated from rpc powermanage.v1.AgentService.Register
         */
        readonly register: {
            readonly name: "Register";
            readonly I: typeof RegisterRequest;
            readonly O: typeof RegisterResponse;
            readonly kind: MethodKind.Unary;
        };
    };
};
//# sourceMappingURL=agent_connect.d.ts.map