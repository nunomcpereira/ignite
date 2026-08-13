'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');

const { withServerEnv, makeTempProject } = require('./helpers');

// These exercise runProjectUnitTests end to end against real language
// toolchain Docker images (golang, rust, python, maven — node reuses the
// project's own devDependency-free node:test). They need a running Docker
// daemon (and, for Maven, network access to pull junit-jupiter), so they
// skip themselves rather than fail when Docker isn't available — same
// pattern as the gitleaks integration tests in secrets-scan.test.js.
function hasDocker() {
  return new Promise((resolve) => {
    execFile('docker', ['info', '--format', '{{.ServerVersion}}'], (err) => resolve(!err));
  });
}

function collectLog() {
  const lines = [];
  const log = (line) => lines.push(line);
  log.lines = lines;
  return log;
}

test('runProjectUnitTests: no recognized project — skips without touching Docker', withServerEnv({}, async (mod) => {
  const dir = await makeTempProject({ 'README.md': '# just docs, no test project\n' });
  const log = collectLog();
  const result = await mod.runProjectUnitTests(dir, log);
  assert.equal(result.ran, false);
  assert.ok(log.lines.some((l) => /skipping unit test run/i.test(l)));
}));

test('runProjectUnitTests: Node.js project — npm test runs inside node:*-alpine', async (t) => {
  if (!await hasDocker()) return t.skip('Docker daemon not available in this environment');
  await withServerEnv({}, async (mod) => {
    const dir = await makeTempProject({
      'package.json': JSON.stringify({
        name: 'sample-node', version: '1.0.0', private: true,
        scripts: { test: 'node --test' },
      }, null, 2),
      'sample.test.js': `
        const test = require('node:test');
        const assert = require('node:assert/strict');
        test('adds numbers', () => { assert.equal(1 + 2, 3); });
      `,
    });
    const log = collectLog();
    const result = await mod.runProjectUnitTests(dir, log);
    assert.equal(result.ran, true);
    assert.deepEqual(result.languages, ['Node.js']);
    assert.ok(log.lines.some((l) => l.includes('✓ Node.js unit tests passed.')));
  })();
});

test('runProjectUnitTests: Go project — go test runs inside golang:alpine', async (t) => {
  if (!await hasDocker()) return t.skip('Docker daemon not available in this environment');
  await withServerEnv({}, async (mod) => {
    const dir = await makeTempProject({
      'go.mod': 'module sample\n\ngo 1.23\n',
      'sample.go': `
        package sample

        func Add(a, b int) int { return a + b }
      `,
      'sample_test.go': `
        package sample

        import "testing"

        func TestAdd(t *testing.T) {
          if Add(2, 3) != 5 {
            t.Fatal("Add(2, 3) != 5")
          }
        }
      `,
    });
    const log = collectLog();
    const result = await mod.runProjectUnitTests(dir, log);
    assert.equal(result.ran, true);
    assert.deepEqual(result.languages, ['Go']);
    assert.ok(log.lines.some((l) => l.includes('✓ Go unit tests passed.')));
  })();
});

test('runProjectUnitTests: Rust project — cargo test runs inside rust:slim', async (t) => {
  if (!await hasDocker()) return t.skip('Docker daemon not available in this environment');
  await withServerEnv({}, async (mod) => {
    const dir = await makeTempProject({
      'Cargo.toml': `
        [package]
        name = "sample"
        version = "0.1.0"
        edition = "2021"
      `,
      'src/lib.rs': `
        pub fn add(a: i32, b: i32) -> i32 { a + b }

        #[cfg(test)]
        mod tests {
          use super::*;

          #[test]
          fn it_adds() {
            assert_eq!(add(2, 2), 4);
          }
        }
      `,
    });
    const log = collectLog();
    const result = await mod.runProjectUnitTests(dir, log);
    assert.equal(result.ran, true);
    assert.deepEqual(result.languages, ['Rust']);
    assert.ok(log.lines.some((l) => l.includes('✓ Rust unit tests passed.')));
  })();
});

test('runProjectUnitTests: Python project — pytest runs inside python:slim', async (t) => {
  if (!await hasDocker()) return t.skip('Docker daemon not available in this environment');
  await withServerEnv({}, async (mod) => {
    const dir = await makeTempProject({
      'requirements.txt': '',
      'sample.py': `def add(a, b):
    return a + b
`,
      'test_sample.py': `from sample import add

def test_add():
    assert add(2, 3) == 5
`,
    });
    const log = collectLog();
    const result = await mod.runProjectUnitTests(dir, log);
    assert.equal(result.ran, true);
    assert.deepEqual(result.languages, ['Python']);
    assert.ok(log.lines.some((l) => l.includes('✓ Python unit tests passed.')));
  })();
});

test('runProjectUnitTests: Java (Maven) project — mvn test runs inside maven:eclipse-temurin', async (t) => {
  if (!await hasDocker()) return t.skip('Docker daemon not available in this environment');
  await withServerEnv({}, async (mod) => {
    const dir = await makeTempProject({
      'pom.xml': `
        <project xmlns="http://maven.apache.org/POM/4.0.0">
          <modelVersion>4.0.0</modelVersion>
          <groupId>com.example</groupId>
          <artifactId>sample</artifactId>
          <version>1.0</version>
          <properties>
            <maven.compiler.source>21</maven.compiler.source>
            <maven.compiler.target>21</maven.compiler.target>
            <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
          </properties>
          <dependencies>
            <dependency>
              <groupId>org.junit.jupiter</groupId>
              <artifactId>junit-jupiter</artifactId>
              <version>5.10.2</version>
              <scope>test</scope>
            </dependency>
          </dependencies>
          <build>
            <plugins>
              <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-surefire-plugin</artifactId>
                <version>3.2.5</version>
              </plugin>
            </plugins>
          </build>
        </project>
      `,
      'src/test/java/SampleTest.java': `
        import org.junit.jupiter.api.Test;
        import static org.junit.jupiter.api.Assertions.assertEquals;

        class SampleTest {
          @Test
          void addsNumbers() {
            assertEquals(4, 2 + 2);
          }
        }
      `,
    });
    const log = collectLog();
    const result = await mod.runProjectUnitTests(dir, log);
    assert.equal(result.ran, true);
    assert.deepEqual(result.languages, ['Java (Maven)']);
    assert.ok(log.lines.some((l) => l.includes('✓ Java (Maven) unit tests passed.')));
  })();
});
