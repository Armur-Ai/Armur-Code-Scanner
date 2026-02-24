// Intentionally insecure JavaScript code for testing purposes.

// CWE-798: Hardcoded credential
const DB_PASSWORD = "admin123";

// CWE-89: SQL injection
function sqlInjection(db, userInput) {
  return db.query("SELECT * FROM users WHERE name = '" + userInput + "'");
}

// CWE-79: XSS via innerHTML
function xssVulnerable(userInput) {
  document.getElementById("output").innerHTML = userInput;
}

// CWE-78: Command injection via eval
function evalInjection(userCode) {
  return eval(userCode); // eslint-disable-line no-eval
}

// No-op function with unused variable (dead code)
function unusedFunction() {
  var unusedVar = 42;
  return "never called";
}

// Overly complex function (cyclomatic complexity)
function complexLogic(a, b, c, d, e) {
  if (a > 0) {
    if (b > 0) {
      if (c > 0) {
        if (d > 0) {
          if (e > 0) {
            return a + b + c + d + e;
          } else {
            return a + b + c + d;
          }
        } else {
          return a + b + c;
        }
      } else {
        return a + b;
      }
    } else {
      return a;
    }
  }
  return 0;
}

module.exports = { sqlInjection, xssVulnerable, evalInjection, complexLogic };
