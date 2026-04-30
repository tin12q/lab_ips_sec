import { test, expect } from '@playwright/test';
import { execSync } from 'child_process';

const DASHBOARD_URL = 'http://127.0.0.1:8080';
const WRITE_TOKEN = execSync('docker exec ms_dashboard cat /tmp/minisnort-dashboard-token', { encoding: 'utf-8' }).trim();

test.describe('MiniSnort Dashboard E2E', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto(DASHBOARD_URL);
    await page.waitForSelector('#connection-status', { state: 'visible' });
  });

  test('should load dashboard and show live connection', async ({ page }) => {
    await expect(page.locator('#connection-status')).toContainText('Live');
    await expect(page.locator('#connection-status')).toHaveAttribute('data-status', 'live');
  });

  test('should load existing rules as list cards', async ({ page }) => {
    await page.waitForSelector('#rule-list', { state: 'visible' });
    await expect(page.locator('#rule-list .rule-card').first()).toBeVisible();
    await expect(page.locator('#rule-list-count')).not.toHaveText('0');
  });

  test('should switch to advanced text mode', async ({ page }) => {
    await page.locator('#mode-text').click();
    await expect(page.locator('#text-mode')).toBeVisible();
    await expect(page.locator('#list-mode')).toBeHidden();
    await expect(page.locator('#rules-text')).toBeVisible();
  });

  test('should validate rules in advanced mode', async ({ page }) => {
    await page.locator('#mode-text').click();
    await page.locator('#rules-text').fill('invalid rule without sid');
    await page.locator('#validate-rules').click();
    await expect(page.locator('#save-message')).toContainText('missing sid');
  });

  test('should prevent duplicate SID validation in advanced mode', async ({ page }) => {
    await page.locator('#mode-text').click();

    const duplicateRules = `
alert tcp any any -> any any (msg:"Test 1"; sid:9999; rev:1;)
alert tcp any any -> any any (msg:"Test 2"; sid:9999; rev:1;)
    `.trim();

    await page.locator('#rules-text').fill(duplicateRules);
    await page.locator('#validate-rules').click();
    await expect(page.locator('#save-message')).toContainText('Duplicate SIDs: 9999');
  });

  test('should show dirty indicator when rules modified from list mode', async ({ page }) => {
    await page.locator('#add-rule-btn').click();

    const sid = `2${Date.now().toString().slice(-6)}`;
    await page.locator('#rule-form [name="msg"]').fill('Dirty test rule');
    await page.locator('#rule-form [name="sid"]').fill(sid);
    await page.locator('#rule-form button[type="submit"]').click();

    await expect(page.locator('#dirty-indicator')).toBeVisible();
    await expect(page.locator('#save-rules')).toBeEnabled();
  });

  test('should disable save button when no changes', async ({ page }) => {
    await page.waitForSelector('#save-rules', { state: 'visible' });
    await expect(page.locator('#save-rules')).toBeDisabled();
  });

  test('should add rule via dialog and save with write token', async ({ page }) => {
    const sid = `3${Date.now().toString().slice(-6)}`;

    await page.locator('#add-rule-btn').click();
    await expect(page.locator('#rule-dialog')).toBeVisible();

    await page.locator('#rule-form [name="action"]').selectOption('drop');
    await page.locator('#rule-form [name="protocol"]').selectOption('tcp');
    await page.locator('#rule-form [name="srcIp"]').fill('any');
    await page.locator('#rule-form [name="srcPort"]').fill('any');
    await page.locator('#rule-form [name="dstIp"]').fill('$HOME_NET');
    await page.locator('#rule-form [name="dstPort"]').fill('80');
    await page.locator('#rule-form [name="msg"]').fill('E2E Add Rule');
    await page.locator('#rule-form [name="sid"]').fill(sid);
    await page.locator('#rule-form [name="rev"]').fill('1');

    await page.locator('#rule-form button[type="submit"]').click();
    await expect(page.locator('#rule-dialog')).toBeHidden();

    await expect(page.locator('#rule-list')).toContainText(`SID: ${sid}`);

    await page.locator('#write-token').fill(WRITE_TOKEN);
    await page.locator('#save-rules').click();
    await expect(page.locator('#save-message')).toContainText('saved', { timeout: 10000 });
  });

  test('should edit an existing rule via dialog', async ({ page }) => {
    const firstRule = page.locator('#rule-list .rule-card').first();
    await firstRule.locator('button[data-rule-edit]').click();

    await expect(page.locator('#dialog-title')).toContainText('EDIT_RULE');
    await page.locator('#rule-form [name="msg"]').fill('Edited by E2E');
    await page.locator('#rule-form button[type="submit"]').click();

    await expect(firstRule).toContainText('Edited by E2E');
  });

  test('should delete a rule from list', async ({ page }) => {
    const initialCount = await page.locator('#rule-list .rule-card').count();
    page.on('dialog', (dialog) => dialog.accept());

    await page.locator('#rule-list .rule-card').first().locator('button[data-rule-delete]').click();
    await expect(page.locator('#rule-list .rule-card')).toHaveCount(initialCount - 1);
  });

  test('should enable and disable a rule', async ({ page }) => {
    const firstCard = page.locator('#rule-list .rule-card').first();
    const toggle = firstCard.locator('input[data-rule-enable]');

    await expect(toggle).toBeChecked();
    await toggle.uncheck();
    await expect(toggle).not.toBeChecked();
    await expect(firstCard).toHaveClass(/is-disabled/);

    await toggle.check();
    await expect(toggle).toBeChecked();
  });

  test('should clear session and truncate alert log', async ({ page }) => {
    await page.locator('#write-token').fill(WRITE_TOKEN);

    page.on('dialog', (dialog) => dialog.accept());
    await page.locator('#clear-session').click();

    await expect(page.locator('#save-message')).toContainText('cleared', { timeout: 5000 });
    await expect(page.locator('#alert-count')).toContainText('0');
  });

  test('should toggle auto-scroll', async ({ page }) => {
    const autoScrollCheckbox = page.locator('#auto-scroll');
    await expect(autoScrollCheckbox).toBeChecked();

    await autoScrollCheckbox.uncheck();
    await expect(autoScrollCheckbox).not.toBeChecked();
  });

  test('should toggle drop-only filter', async ({ page }) => {
    const filterCheckbox = page.locator('#filter-drop');
    await expect(filterCheckbox).not.toBeChecked();

    await filterCheckbox.check();
    await expect(filterCheckbox).toBeChecked();
  });

  test('should format rules spacing in advanced mode', async ({ page }) => {
    await page.locator('#mode-text').click();

    const messyRules = `alert tcp any any -> any any (msg:"Test"; sid:7777; rev:1;)


alert tcp any any -> any any (msg:"Test2"; sid:7778; rev:1;)`;

    await page.locator('#rules-text').fill(messyRules);
    await page.locator('#format-rules').click();

    const formatted = await page.locator('#rules-text').inputValue();
    expect(formatted).toContain('\n\n');
  });

  test('should show rule hints', async ({ page }) => {
    await page.locator('#mode-text').click();
    await page.locator('#rules-text').fill('alert tcp any any -> any any (msg:"Test"; sid:6666; rev:1;)');
    await page.waitForTimeout(300);

    await expect(page.locator('#rule-hints')).toContainText('1 active rules');
  });

  test('should clear view (client-side only)', async ({ page }) => {
    await page.locator('#clear-alerts').click();
    await expect(page.locator('#alert-count')).toContainText('0');
  });

  test('should reload rules from server', async ({ page }) => {
    await page.locator('#add-rule-btn').click();
    const sid = `4${Date.now().toString().slice(-6)}`;
    await page.locator('#rule-form [name="msg"]').fill('Temporary UI rule');
    await page.locator('#rule-form [name="sid"]').fill(sid);
    await page.locator('#rule-form button[type="submit"]').click();

    await page.locator('#reload-rules').click();
    await expect(page.locator('#save-message')).toContainText('Loaded', { timeout: 5000 });
    await expect(page.locator('#rule-list')).not.toContainText(`SID: ${sid}`);
  });

  test('should insert snippet via click in advanced mode', async ({ page }) => {
    await page.locator('#mode-text').click();
    await page.locator('#rules-text').fill('');

    const snippet = page.locator('.cyber-snippet').first();
    await snippet.click();

    const rulesText = await page.locator('#rules-text').inputValue();
    expect(rulesText.length).toBeGreaterThan(0);
    expect(rulesText).toContain('sid:');
  });

  test('should show status metrics', async ({ page }) => {
    await expect(page.locator('#rule-count')).toBeVisible();
    await expect(page.locator('#alert-count')).toBeVisible();
    await expect(page.locator('#drop-count')).toBeVisible();
    await expect(page.locator('#top-sid')).toBeVisible();
  });

  test('should poll alerts via long-poll', async ({ page }) => {
    const initialOffset = await page.locator('#tail-offset').textContent();
    expect(initialOffset).toContain('bytes');

    await page.waitForTimeout(2000);

    const updatedOffset = await page.locator('#tail-offset').textContent();
    expect(updatedOffset).toContain('bytes');
  });
});
