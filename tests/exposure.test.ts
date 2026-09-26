import { describe, expect, it } from "vitest";
import { exposureMap, exposureOf } from "@/client/exposure";

const types = new Map([
  ["user", "actor"],
  ["web", "frontend"],
  ["api", "api"],
  ["db", "database"],
  ["stripe", "external_service"],
  ["idp", "auth_provider"],
  ["webhook", "backend"],
]);
const c = (id: string) => ({ id, type: types.get(id)! });
const f = (source: string, target: string) => ({ source, target });

describe("exposureOf", () => {
  it("is external for external services and auth providers, whatever their flows", () => {
    expect(exposureOf(c("stripe"), [f("user", "stripe")], types)).toBe("external");
    expect(exposureOf(c("idp"), [], types)).toBe("external");
  });

  it("is edge for actors and frontends", () => {
    expect(exposureOf(c("user"), [], types)).toBe("edge");
    expect(exposureOf(c("web"), [], types)).toBe("edge");
  });

  it("is edge for any component with an inbound flow from an actor", () => {
    expect(exposureOf(c("webhook"), [f("user", "webhook")], types)).toBe("edge");
  });

  it("is internal otherwise, including for an outbound flow to an actor", () => {
    expect(exposureOf(c("api"), [f("web", "api"), f("api", "user")], types)).toBe("internal");
    expect(exposureOf(c("db"), [f("api", "db")], types)).toBe("internal");
  });
});

describe("exposureMap", () => {
  it("rates every component once, by id", () => {
    const map = exposureMap([...types.keys()].map(c), [f("user", "web"), f("user", "webhook")]);
    expect(Object.fromEntries(map)).toEqual({
      user: "edge", web: "edge", api: "internal", db: "internal",
      stripe: "external", idp: "external", webhook: "edge",
    });
  });
});
