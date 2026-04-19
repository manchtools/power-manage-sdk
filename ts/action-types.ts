// Pure action type conversion utilities — no framework dependencies.
import { ActionType } from '../gen/ts/pm/v1/actions_pb';

export { ActionType };

/**
 * Convert a string action type name to the ActionType enum value.
 */
export function getActionTypeEnum(type: string): ActionType {
	switch (type) {
		case 'PACKAGE':
			return ActionType.PACKAGE;
		case 'REPOSITORY':
			return ActionType.REPOSITORY;
		case 'UPDATE':
			return ActionType.UPDATE;
		case 'SHELL':
			return ActionType.SHELL;
		case 'SERVICE':
			return ActionType.SERVICE;
		case 'FILE':
			return ActionType.FILE;
		case 'APP_IMAGE':
			return ActionType.APP_IMAGE;
		case 'DEB':
			return ActionType.DEB;
		case 'RPM':
			return ActionType.RPM;
		case 'FLATPAK':
			return ActionType.FLATPAK;
		case 'DIRECTORY':
			return ActionType.DIRECTORY;
		case 'USER':
			return ActionType.USER;
		case 'SSH':
			return ActionType.SSH;
		case 'SSHD':
			return ActionType.SSHD;
		case 'ADMIN_POLICY':
			return ActionType.ADMIN_POLICY;
		case 'LPS':
			return ActionType.LPS;
		case 'GROUP':
			return ActionType.GROUP;
		case 'ENCRYPTION':
			return ActionType.ENCRYPTION;
		case 'SCRIPT_RUN':
			return ActionType.SCRIPT_RUN;
		case 'WIFI':
			return ActionType.WIFI;
		case 'AGENT_UPDATE':
			return ActionType.AGENT_UPDATE;
		case 'COMPLIANCE_CHECK':
			return ActionType.SHELL;
		default:
			return ActionType.UNSPECIFIED;
	}
}

/**
 * Convert an ActionType enum value to its string name.
 */
export function actionTypeToString(type: ActionType): string {
	switch (type) {
		case ActionType.PACKAGE:
			return 'PACKAGE';
		case ActionType.REPOSITORY:
			return 'REPOSITORY';
		case ActionType.UPDATE:
			return 'UPDATE';
		case ActionType.SHELL:
			return 'SHELL';
		case ActionType.SERVICE:
			return 'SERVICE';
		case ActionType.FILE:
			return 'FILE';
		case ActionType.APP_IMAGE:
			return 'APP_IMAGE';
		case ActionType.DEB:
			return 'DEB';
		case ActionType.RPM:
			return 'RPM';
		case ActionType.FLATPAK:
			return 'FLATPAK';
		case ActionType.DIRECTORY:
			return 'DIRECTORY';
		case ActionType.USER:
			return 'USER';
		case ActionType.SSH:
			return 'SSH';
		case ActionType.SSHD:
			return 'SSHD';
		case ActionType.ADMIN_POLICY:
			return 'ADMIN_POLICY';
		case ActionType.LPS:
			return 'LPS';
		case ActionType.GROUP:
			return 'GROUP';
		case ActionType.ENCRYPTION:
			return 'ENCRYPTION';
		case ActionType.SCRIPT_RUN:
			return 'SCRIPT_RUN';
		case ActionType.WIFI:
			return 'WIFI';
		case ActionType.AGENT_UPDATE:
			return 'AGENT_UPDATE';
		default:
			return 'UNSPECIFIED';
	}
}

/**
 * Static list of action type options (value + enum) for forms and filters.
 */
export const ACTION_TYPE_OPTIONS = [
	{ value: 'PACKAGE', type: ActionType.PACKAGE },
	{ value: 'REPOSITORY', type: ActionType.REPOSITORY },
	{ value: 'UPDATE', type: ActionType.UPDATE },
	{ value: 'SHELL', type: ActionType.SHELL },
	{ value: 'SERVICE', type: ActionType.SERVICE },
	{ value: 'FILE', type: ActionType.FILE },
	{ value: 'DIRECTORY', type: ActionType.DIRECTORY },
	{ value: 'APP_IMAGE', type: ActionType.APP_IMAGE },
	{ value: 'DEB', type: ActionType.DEB },
	{ value: 'RPM', type: ActionType.RPM },
	{ value: 'FLATPAK', type: ActionType.FLATPAK },
	{ value: 'USER', type: ActionType.USER },
	{ value: 'SSH', type: ActionType.SSH },
	{ value: 'SSHD', type: ActionType.SSHD },
	{ value: 'ADMIN_POLICY', type: ActionType.ADMIN_POLICY },
	{ value: 'LPS', type: ActionType.LPS },
	{ value: 'ENCRYPTION', type: ActionType.ENCRYPTION },
	{ value: 'GROUP', type: ActionType.GROUP },
	{ value: 'AGENT_UPDATE', type: ActionType.AGENT_UPDATE }
] as const;
