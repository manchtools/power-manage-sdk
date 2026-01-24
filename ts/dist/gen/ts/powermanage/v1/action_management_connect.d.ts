import { AddActionSetsToDefinitionRequest, AddActionSetsToDefinitionResponse, AddActionsToSetRequest, AddActionsToSetResponse, CreateActionSetRequest, CreateActionSetResponse, CreateAssignmentRequest, CreateAssignmentResponse, CreateDefinitionRequest, CreateDefinitionResponse, CreateManagedActionRequest, CreateManagedActionResponse, DeleteActionSetRequest, DeleteActionSetResponse, DeleteAssignmentRequest, DeleteAssignmentResponse, DeleteDefinitionRequest, DeleteDefinitionResponse, DeleteManagedActionRequest, DeleteManagedActionResponse, GetActionSetRequest, GetActionSetResponse, GetDefinitionRequest, GetDefinitionResponse, GetEffectiveActionsRequest, GetEffectiveActionsResponse, GetManagedActionRequest, GetManagedActionResponse, ListActionSetsRequest, ListActionSetsResponse, ListAssignmentsRequest, ListAssignmentsResponse, ListDefinitionsRequest, ListDefinitionsResponse, ListManagedActionsRequest, ListManagedActionsResponse, RemoveActionSetsFromDefinitionRequest, RemoveActionSetsFromDefinitionResponse, RemoveActionsFromSetRequest, RemoveActionsFromSetResponse, UpdateActionSetRequest, UpdateActionSetResponse, UpdateDefinitionRequest, UpdateDefinitionResponse, UpdateManagedActionRequest, UpdateManagedActionResponse } from "./action_management_pb.js";
import { MethodKind } from "@bufbuild/protobuf";
/**
 * @generated from service powermanage.v1.ActionManagementService
 */
export declare const ActionManagementService: {
    readonly typeName: "powermanage.v1.ActionManagementService";
    readonly methods: {
        /**
         * Create a managed action
         *
         * @generated from rpc powermanage.v1.ActionManagementService.CreateManagedAction
         */
        readonly createManagedAction: {
            readonly name: "CreateManagedAction";
            readonly I: typeof CreateManagedActionRequest;
            readonly O: typeof CreateManagedActionResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Get managed action by ID
         *
         * @generated from rpc powermanage.v1.ActionManagementService.GetManagedAction
         */
        readonly getManagedAction: {
            readonly name: "GetManagedAction";
            readonly I: typeof GetManagedActionRequest;
            readonly O: typeof GetManagedActionResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * List managed actions
         *
         * @generated from rpc powermanage.v1.ActionManagementService.ListManagedActions
         */
        readonly listManagedActions: {
            readonly name: "ListManagedActions";
            readonly I: typeof ListManagedActionsRequest;
            readonly O: typeof ListManagedActionsResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Update managed action
         *
         * @generated from rpc powermanage.v1.ActionManagementService.UpdateManagedAction
         */
        readonly updateManagedAction: {
            readonly name: "UpdateManagedAction";
            readonly I: typeof UpdateManagedActionRequest;
            readonly O: typeof UpdateManagedActionResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Delete managed action
         *
         * @generated from rpc powermanage.v1.ActionManagementService.DeleteManagedAction
         */
        readonly deleteManagedAction: {
            readonly name: "DeleteManagedAction";
            readonly I: typeof DeleteManagedActionRequest;
            readonly O: typeof DeleteManagedActionResponse;
            readonly kind: MethodKind.Unary;
        };
    };
};
/**
 * @generated from service powermanage.v1.ActionSetService
 */
export declare const ActionSetService: {
    readonly typeName: "powermanage.v1.ActionSetService";
    readonly methods: {
        /**
         * Create an action set
         *
         * @generated from rpc powermanage.v1.ActionSetService.CreateActionSet
         */
        readonly createActionSet: {
            readonly name: "CreateActionSet";
            readonly I: typeof CreateActionSetRequest;
            readonly O: typeof CreateActionSetResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Get action set by ID
         *
         * @generated from rpc powermanage.v1.ActionSetService.GetActionSet
         */
        readonly getActionSet: {
            readonly name: "GetActionSet";
            readonly I: typeof GetActionSetRequest;
            readonly O: typeof GetActionSetResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * List action sets
         *
         * @generated from rpc powermanage.v1.ActionSetService.ListActionSets
         */
        readonly listActionSets: {
            readonly name: "ListActionSets";
            readonly I: typeof ListActionSetsRequest;
            readonly O: typeof ListActionSetsResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Update action set
         *
         * @generated from rpc powermanage.v1.ActionSetService.UpdateActionSet
         */
        readonly updateActionSet: {
            readonly name: "UpdateActionSet";
            readonly I: typeof UpdateActionSetRequest;
            readonly O: typeof UpdateActionSetResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Delete action set
         *
         * @generated from rpc powermanage.v1.ActionSetService.DeleteActionSet
         */
        readonly deleteActionSet: {
            readonly name: "DeleteActionSet";
            readonly I: typeof DeleteActionSetRequest;
            readonly O: typeof DeleteActionSetResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Add actions to set
         *
         * @generated from rpc powermanage.v1.ActionSetService.AddActionsToSet
         */
        readonly addActionsToSet: {
            readonly name: "AddActionsToSet";
            readonly I: typeof AddActionsToSetRequest;
            readonly O: typeof AddActionsToSetResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Remove actions from set
         *
         * @generated from rpc powermanage.v1.ActionSetService.RemoveActionsFromSet
         */
        readonly removeActionsFromSet: {
            readonly name: "RemoveActionsFromSet";
            readonly I: typeof RemoveActionsFromSetRequest;
            readonly O: typeof RemoveActionsFromSetResponse;
            readonly kind: MethodKind.Unary;
        };
    };
};
/**
 * @generated from service powermanage.v1.DefinitionService
 */
export declare const DefinitionService: {
    readonly typeName: "powermanage.v1.DefinitionService";
    readonly methods: {
        /**
         * Create a definition
         *
         * @generated from rpc powermanage.v1.DefinitionService.CreateDefinition
         */
        readonly createDefinition: {
            readonly name: "CreateDefinition";
            readonly I: typeof CreateDefinitionRequest;
            readonly O: typeof CreateDefinitionResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Get definition by ID
         *
         * @generated from rpc powermanage.v1.DefinitionService.GetDefinition
         */
        readonly getDefinition: {
            readonly name: "GetDefinition";
            readonly I: typeof GetDefinitionRequest;
            readonly O: typeof GetDefinitionResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * List definitions
         *
         * @generated from rpc powermanage.v1.DefinitionService.ListDefinitions
         */
        readonly listDefinitions: {
            readonly name: "ListDefinitions";
            readonly I: typeof ListDefinitionsRequest;
            readonly O: typeof ListDefinitionsResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Update definition
         *
         * @generated from rpc powermanage.v1.DefinitionService.UpdateDefinition
         */
        readonly updateDefinition: {
            readonly name: "UpdateDefinition";
            readonly I: typeof UpdateDefinitionRequest;
            readonly O: typeof UpdateDefinitionResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Delete definition
         *
         * @generated from rpc powermanage.v1.DefinitionService.DeleteDefinition
         */
        readonly deleteDefinition: {
            readonly name: "DeleteDefinition";
            readonly I: typeof DeleteDefinitionRequest;
            readonly O: typeof DeleteDefinitionResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Add action sets to definition
         *
         * @generated from rpc powermanage.v1.DefinitionService.AddActionSetsToDefinition
         */
        readonly addActionSetsToDefinition: {
            readonly name: "AddActionSetsToDefinition";
            readonly I: typeof AddActionSetsToDefinitionRequest;
            readonly O: typeof AddActionSetsToDefinitionResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Remove action sets from definition
         *
         * @generated from rpc powermanage.v1.DefinitionService.RemoveActionSetsFromDefinition
         */
        readonly removeActionSetsFromDefinition: {
            readonly name: "RemoveActionSetsFromDefinition";
            readonly I: typeof RemoveActionSetsFromDefinitionRequest;
            readonly O: typeof RemoveActionSetsFromDefinitionResponse;
            readonly kind: MethodKind.Unary;
        };
    };
};
/**
 * @generated from service powermanage.v1.AssignmentService
 */
export declare const AssignmentService: {
    readonly typeName: "powermanage.v1.AssignmentService";
    readonly methods: {
        /**
         * Create an assignment
         *
         * @generated from rpc powermanage.v1.AssignmentService.CreateAssignment
         */
        readonly createAssignment: {
            readonly name: "CreateAssignment";
            readonly I: typeof CreateAssignmentRequest;
            readonly O: typeof CreateAssignmentResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * List assignments
         *
         * @generated from rpc powermanage.v1.AssignmentService.ListAssignments
         */
        readonly listAssignments: {
            readonly name: "ListAssignments";
            readonly I: typeof ListAssignmentsRequest;
            readonly O: typeof ListAssignmentsResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Delete an assignment
         *
         * @generated from rpc powermanage.v1.AssignmentService.DeleteAssignment
         */
        readonly deleteAssignment: {
            readonly name: "DeleteAssignment";
            readonly I: typeof DeleteAssignmentRequest;
            readonly O: typeof DeleteAssignmentResponse;
            readonly kind: MethodKind.Unary;
        };
        /**
         * Get effective actions for a device (resolves all assignments)
         *
         * @generated from rpc powermanage.v1.AssignmentService.GetEffectiveActions
         */
        readonly getEffectiveActions: {
            readonly name: "GetEffectiveActions";
            readonly I: typeof GetEffectiveActionsRequest;
            readonly O: typeof GetEffectiveActionsResponse;
            readonly kind: MethodKind.Unary;
        };
    };
};
//# sourceMappingURL=action_management_connect.d.ts.map