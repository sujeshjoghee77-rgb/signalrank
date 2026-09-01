/**
 * SignalRank - Lightweight Browser & JS Unit Test Framework
 * 
 * Provides describe, it, expect, and assertion reporting.
 */

class TestRunner {
  constructor() {
    this.suites = [];
    this.currentSuite = null;
    this.results = {
      total: 0,
      passed: 0,
      failed: 0,
      durationMs: 0,
      suites: []
    };
  }

  describe(suiteName, fn) {
    const suite = {
      name: suiteName,
      tests: [],
      passed: 0,
      failed: 0
    };
    this.suites.push(suite);
    this.currentSuite = suite;
    fn();
    this.currentSuite = null;
  }

  it(testName, fn) {
    if (!this.currentSuite) {
      throw new Error(`Test "${testName}" must be inside a describe block.`);
    }
    this.currentSuite.tests.push({
      name: testName,
      fn
    });
  }

  async runAll() {
    const startTime = performance.now();
    this.results = {
      total: 0,
      passed: 0,
      failed: 0,
      durationMs: 0,
      suites: []
    };

    for (const suite of this.suites) {
      const suiteResult = {
        name: suite.name,
        passed: 0,
        failed: 0,
        tests: []
      };

      for (const test of suite.tests) {
        this.results.total++;
        const testStartTime = performance.now();
        let status = 'passed';
        let error = null;

        try {
          await test.fn();
          suiteResult.passed++;
          this.results.passed++;
        } catch (err) {
          status = 'failed';
          error = err;
          suiteResult.failed++;
          this.results.failed++;
        }

        const testDuration = performance.now() - testStartTime;
        suiteResult.tests.push({
          name: test.name,
          status,
          durationMs: Math.round(testDuration * 100) / 100,
          error: error ? { message: error.message, stack: error.stack } : null
        });
      }

      this.results.suites.push(suiteResult);
    }

    this.results.durationMs = Math.round((performance.now() - startTime) * 100) / 100;
    return this.results;
  }
}

export const runner = new TestRunner();
export const describe = (name, fn) => runner.describe(name, fn);
export const it = (name, fn) => runner.it(name, fn);

export function expect(actual) {
  return {
    toBe(expected) {
      if (actual !== expected) {
        throw new Error(`Expected ${JSON.stringify(actual)} to be ${JSON.stringify(expected)}`);
      }
    },
    toEqual(expected) {
      const actualStr = JSON.stringify(actual);
      const expectedStr = JSON.stringify(expected);
      if (actualStr !== expectedStr) {
        throw new Error(`Expected ${actualStr} to deeply equal ${expectedStr}`);
      }
    },
    toBeCloseTo(expected, precision = 2) {
      const diff = Math.abs(actual - expected);
      const tolerance = Math.pow(10, -precision) / 2;
      if (diff > tolerance) {
        throw new Error(`Expected ${actual} to be close to ${expected} (tolerance: ${tolerance}, diff: ${diff})`);
      }
    },
    toBeGreaterThan(expected) {
      if (!(actual > expected)) {
        throw new Error(`Expected ${actual} to be greater than ${expected}`);
      }
    },
    toBeGreaterThanOrEqual(expected) {
      if (!(actual >= expected)) {
        throw new Error(`Expected ${actual} to be greater than or equal to ${expected}`);
      }
    },
    toBeLessThan(expected) {
      if (!(actual < expected)) {
        throw new Error(`Expected ${actual} to be less than ${expected}`);
      }
    },
    toBeLessThanOrEqual(expected) {
      if (!(actual <= expected)) {
        throw new Error(`Expected ${actual} to be less than or equal to ${expected}`);
      }
    },
    toBeTruthy() {
      if (!actual) {
        throw new Error(`Expected ${JSON.stringify(actual)} to be truthy`);
      }
    },
    toBeFalsy() {
      if (actual) {
        throw new Error(`Expected ${JSON.stringify(actual)} to be falsy`);
      }
    }
  };
}
