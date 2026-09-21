import {
  type Browser,
  type BrowserContext,
  expect,
  type Page,
} from "@playwright/test";

export function useBrowser(browser: Browser, context: BrowserContext, page: Page) {
  expect(browser).toBeDefined();
  expect(context).toBeDefined();
  expect(page).toBeDefined();
}
