// Front-end expression evaluator used by agent tests.

function evaluateExpression(expr) {
  const out = eval(expr);
  return out;
}

module.exports = { evaluateExpression };
