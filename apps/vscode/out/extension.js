"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.activate = activate;
exports.deactivate = deactivate;
const vscode = __importStar(require("vscode"));
const validate_1 = require("./validate");
const scenarios_1 = require("./scenarios");
const TEMPLATE = {
    id: 'user.my-rule',
    name: 'My rule',
    technique: 'T1176.001',
    scope: 'management',
    condition: { field: 'payload.installType', op: 'eq', value: 'development' },
    responses: ['alert', 'disableExtension'],
    enabled: true,
};
function activate(context) {
    context.subscriptions.push(vscode.commands.registerCommand('attack.newRule', async () => {
        const doc = await vscode.workspace.openTextDocument({
            language: 'json',
            content: JSON.stringify(TEMPLATE, null, 2),
        });
        await vscode.window.showTextDocument(doc);
        void vscode.window.showInformationMessage('Save as *.attackrule.json for schema validation + completion.');
    }), vscode.commands.registerCommand('attack.validateRule', () => {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            void vscode.window.showWarningMessage('Open a rule file first.');
            return;
        }
        let parsed;
        try {
            parsed = JSON.parse(editor.document.getText());
        }
        catch (err) {
            void vscode.window.showErrorMessage(`Not valid JSON: ${err.message}`);
            return;
        }
        const result = (0, validate_1.validateAuthoredRule)(parsed);
        if (result.ok) {
            void vscode.window.showInformationMessage('✓ Valid 0x13d::att&ck rule — ready to import.');
        }
        else {
            void vscode.window.showErrorMessage(`Rule rejected:\n• ${result.errors.join('\n• ')}`);
        }
    }), vscode.commands.registerCommand('attack.runScenarios', () => (0, scenarios_1.runScenarioReport)()));
}
function deactivate() {
    // nothing to clean up
}
//# sourceMappingURL=extension.js.map