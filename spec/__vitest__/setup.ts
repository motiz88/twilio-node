import { createRequire } from "module";
import { readFileSync } from "fs";
import { vi } from "vitest";
import ts from "typescript";

// Register a custom .ts handler in Node's CJS resolver so that source files
// using `require("./some-module")` (without explicit extension) can resolve
// to their `.ts` counterparts.
//
// We use TypeScript's `transpileModule` rather than Node 24's built-in type
// stripping because Node's stripper keeps `import` statements as ESM, which
// then fails for relative imports without explicit `.js` extensions and for
// packages that lack an `exports` field (e.g. dayjs sub-paths).
// `transpileModule` emits proper CommonJS `require()` calls instead.
const _require = createRequire(import.meta.url);

if (!_require.extensions[".ts"]) {
  _require.extensions[".ts"] = function (
    mod: NodeModule & { _compile(code: string, filename: string): void },
    filename: string
  ) {
    const source = readFileSync(filename, "utf8");
    const { outputText } = ts.transpileModule(source, {
      compilerOptions: {
        module: ts.ModuleKind.CommonJS,
        target: ts.ScriptTarget.ES2020,
        esModuleInterop: true,
        allowSyntheticDefaultImports: true,
      },
      fileName: filename,
    });
    mod._compile(outputText, filename);
  };
}

// Allow existing tests that use the `jest` global to work under Vitest.
(globalThis as any).jest = vi;
