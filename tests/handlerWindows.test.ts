import { describe, expect, it } from "vitest";
import {
  DEFINITION_WINDOW_LINES,
  MAX_DAO_WINDOWS_PER_ELEMENT,
  MAX_HANDLER_WINDOWS_PER_ELEMENT,
  STARTUP_MAX_LINES,
  daoInstances,
  extraWindows,
  handlerDefinitions,
  methodDefinitionLine,
  resolveRequire,
  startupFile,
} from "@/server/analysis/handlerWindows";

const pad = (n: number) => Array.from({ length: n }, (_, i) => `// filler ${i}`).join("\n");

// NodeGoat-shaped files (OWASP/NodeGoat app/routes/allocations.js, app/data/allocations-dao.js).
const ROUTE = [
  'const AllocationsDAO = require("../data/allocations-dao").AllocationsDAO;',
  "function AllocationsHandler(db) {",
  "    const allocationsDAO = new AllocationsDAO(db);",
  "    this.displayAllocations = (req, res, next) => {",
  "        const { userId } = req.params;",
  "        allocationsDAO.getByUserIdAndThreshold(userId, req.query.threshold, (err, a) => {});",
  "    };",
  "}",
].join("\n");
const DAO = [
  "function AllocationsDAO(db) {",
  pad(60),
  "    this.getByUserIdAndThreshold = (userId, threshold, callback) => {",
  "        return { $where: `this.stocks > '${threshold}'` };",
  "    };",
  "}",
].join("\n");
const SERVER = [
  'const express = require("express");',
  "const app = express();",
  pad(100),
  "    // app.use(csrf());",
  "http.createServer(app).listen(4000);",
].join("\n");

const FILES = [
  { path: "app/routes/allocations.js", content: ROUTE },
  { path: "app/data/allocations-dao.js", content: DAO },
  { path: "server.js", content: SERVER },
];

describe("handlerDefinitions", () => {
  it("finds this.x = (req...), function x(req...) and const x = (req...)", () => {
    const content = [
      "this.a = (req, res) => {};",
      "function b(req, res) {}",
      "const c = async (req, res) => {};",
      "this.notHandler = (db) => {};",
      "// this.commented = (req, res) => {};",
    ].join("\n");
    expect(handlerDefinitions(content)).toEqual([
      { name: "a", line: 1 },
      { name: "b", line: 2 },
      { name: "c", line: 3 },
    ]);
  });
});

describe("require and DAO resolution", () => {
  const known = new Set(FILES.map((f) => f.path));

  it("resolves a relative require to a loaded file and ignores packages", () => {
    expect(resolveRequire("app/routes/allocations.js", "../data/allocations-dao", known)).toBe("app/data/allocations-dao.js");
    expect(resolveRequire("app/routes/allocations.js", "express", known)).toBeUndefined();
    expect(resolveRequire("app/routes/allocations.js", "../data/missing", known)).toBeUndefined();
  });

  it("maps a `new X()` instance to X's required file, including destructured requires", () => {
    expect(daoInstances("app/routes/allocations.js", ROUTE, known).get("allocationsDAO")).toEqual({
      className: "AllocationsDAO",
      file: "app/data/allocations-dao.js",
    });
    const destructured = 'const { AllocationsDAO } = require("../data/allocations-dao");\nconst dao = new AllocationsDAO(db);';
    expect(daoInstances("app/routes/x.js", destructured, known).get("dao")?.file).toBe("app/data/allocations-dao.js");
  });

  it("finds a method definition line and not a commented one", () => {
    expect(methodDefinitionLine(DAO, "getByUserIdAndThreshold")).toBe(62);
    expect(methodDefinitionLine("// this.m = () => {}\nthis.m = () => {}", "m")).toBe(2);
    expect(methodDefinitionLine(DAO, "missing")).toBeUndefined();
  });
});

describe("startupFile", () => {
  it("picks the file that creates an express app and listens, shallowest first", () => {
    expect(startupFile(FILES)).toBe("server.js");
    expect(startupFile([{ path: "app/routes/allocations.js", content: ROUTE }])).toBeUndefined();
  });
});

describe("extraWindows", () => {
  it("adds the handler, one DAO hop reaching the $where line, and the startup file", () => {
    const windows = extraWindows([["app/routes/allocations.js"]], FILES);
    expect(windows.map((w) => [w.kind, w.path, w.range, w.label])).toEqual([
      ["handler", "app/routes/allocations.js", [4, 8], "displayAllocations"],
      ["dao", "app/data/allocations-dao.js", [62, 65], "AllocationsDAO.getByUserIdAndThreshold"],
      ["startup", "server.js", [1, 104], "server.js"],
    ]);
    // The $where line (63) and the commented CSRF middleware (line 103) are inside.
    expect(63).toBeGreaterThanOrEqual(windows[1].range[0]);
    expect(103).toBeLessThanOrEqual(windows[2].range[1]);
  });

  it("caps windows per element and lines per window", () => {
    const many = Array.from({ length: 10 }, (_, i) => `this.h${i} = (req, res) => { dao${i}.m(); };`);
    const decls = Array.from({ length: 10 }, (_, i) => `const dao${i} = new D(db);`);
    const route = ['const D = require("./d");', ...decls, ...many].join("\n");
    const d = `this.m = () => {\n${pad(200)}\n};`;
    const windows = extraWindows([["r.js"]], [{ path: "r.js", content: route }, { path: "d.js", content: d }]);
    expect(windows.filter((w) => w.kind === "handler")).toHaveLength(MAX_HANDLER_WINDOWS_PER_ELEMENT);
    expect(windows.filter((w) => w.kind === "dao").length).toBeLessThanOrEqual(MAX_DAO_WINDOWS_PER_ELEMENT);
    for (const w of windows) expect(w.range[1] - w.range[0] + 1).toBeLessThanOrEqual(Math.max(DEFINITION_WINDOW_LINES, STARTUP_MAX_LINES));
    expect(windows.find((w) => w.kind === "dao")?.range).toEqual([1, DEFINITION_WINDOW_LINES]);
  });

  it("adds nothing for a file with no request handlers and no startup file", () => {
    expect(extraWindows([["lib/util.js"]], [{ path: "lib/util.js", content: "function add(a, b) { return a + b; }" }])).toEqual([]);
  });
});
