import * as assert from 'assert';
import * as vscode from 'vscode';
import { suite, test } from 'mocha';

// You can import and use all API from the 'vscode' module
// as well as import your extension to test it
// const myExtension = require('../../extension');

suite('DECOYABLE Extension Test Suite', () => {
  vscode.window.showInformationMessage('Start all tests.');

  test('Sample test', () => {
    assert.strictEqual(-1, [1, 2, 3].indexOf(5));
    assert.strictEqual(-1, [1, 2, 3].indexOf(0));
  });

  test('Extension activation', async () => {
    // Test that the extension activates properly
    const extension = vscode.extensions.getExtension('kolerr-lab.decoyable-security');
    if (extension) {
      await extension.activate();
      assert.ok(extension.isActive);
    } else {
      assert.fail('Extension not found');
    }
  });

  test('Commands registration', async () => {
    // Test that commands are registered
    const commands = await vscode.commands.getCommands(true);
    const decoyableCommands = commands.filter((cmd: string) => cmd.startsWith('decoyable.'));

    assert.ok(decoyableCommands.length > 0, 'DECOYABLE commands should be registered');
    assert.ok(decoyableCommands.includes('decoyable.scanWorkspace'), 'scanWorkspace command should be registered');
    assert.ok(decoyableCommands.includes('decoyable.scanFile'), 'scanFile command should be registered');
  });
});