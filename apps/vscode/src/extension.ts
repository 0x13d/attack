import * as vscode from 'vscode';
import { validateAuthoredRule } from './validate';
import { runScenarioReport } from './scenarios';

const TEMPLATE = {
  id: 'user.my-rule',
  name: 'My rule',
  technique: 'T1176.001',
  scope: 'management',
  condition: { field: 'payload.installType', op: 'eq', value: 'development' },
  responses: ['alert', 'disableExtension'],
  enabled: true,
};

export function activate(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.commands.registerCommand('attack.newRule', async () => {
      const doc = await vscode.workspace.openTextDocument({
        language: 'json',
        content: JSON.stringify(TEMPLATE, null, 2),
      });
      await vscode.window.showTextDocument(doc);
      void vscode.window.showInformationMessage('Save as *.attackrule.json for schema validation + completion.');
    }),

    vscode.commands.registerCommand('attack.validateRule', () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        void vscode.window.showWarningMessage('Open a rule file first.');
        return;
      }
      let parsed: unknown;
      try {
        parsed = JSON.parse(editor.document.getText());
      } catch (err) {
        void vscode.window.showErrorMessage(`Not valid JSON: ${(err as Error).message}`);
        return;
      }
      const result = validateAuthoredRule(parsed);
      if (result.ok) {
        void vscode.window.showInformationMessage('✓ Valid 0x13d::att&ck rule — ready to import.');
      } else {
        void vscode.window.showErrorMessage(`Rule rejected:\n• ${result.errors.join('\n• ')}`);
      }
    }),

    vscode.commands.registerCommand('attack.runScenarios', () => runScenarioReport()),
  );
}

export function deactivate(): void {
  // nothing to clean up
}
