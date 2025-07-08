/* Author: Willem Hengeveld <itsme@xs4all.nl> */
/* https://github.com/nlitsme/bitcoinexplainer */
"use strict";

/*
 * An expression parser.
 * parses expressions with:
 *  - operators: +, -, *, /, ^, **, =
 *  - values: 0xabcd or 1234 numbers, or "x+y" strings
 *  - names: starting with a letter.
 *  - brackets for subexpressions:  3*(4+5)
 *  - function calls:  sqrt(a, b)
 *  - bracketed lists: (1, 2)
 *  - four types of brackets can be used: ([{<>}])

 * use the function `parseexpr` to parse a text string.
 * then use the function `evaluator` to evaluate the expression tree
 * given a evaluation context.

 * the evaluation context must contain the following functions:
 *  class Context {
 *      add(a, b)   //  a+b
 *      sub(a, b)   //  a-b
 *      mul(a, b)   //  a*b
 *      div(a, b)   //  a/b
 *      pow(a, b)   //  a^b  or a**b
 *
 *      numbervalue(a)   // 0x123  or 456   used to convert the string to a value
 *      listvalue(t, a)  // (1, 2)          used to convert a list to a value.
 *      get(name)        // called when using a `name`
 *      set(name, value) // called when assigning to a variable: name=value
 * }
 * And optionally any functions called by name.
 *
 * TODO:
 *   support '.' / DOT operator for method calls,  eg: pt.x   or  x.sqrt()
 *   support unary operators
 *   support comments.
 */


class NumValue  {
    constructor(value) { this.value = value; }
    toString() { return "NUM:["+this.value+"]"; }
};
class Name  {
    constructor(name) { this.name = name; }
    toString() { return "NAME:["+this.name+"]"; }
};
class TextValue {
    // text values can not be nested, so no escaped quotes.
    constructor(value) { this.value = value.substring(1, value.length-1); }
    toString() { return "TEXT:["+this.value+"]"; }
};

class Operator  {
    constructor(op) {
        this.op = op;
        this.args = [];
        this.isUnary = false; // Initialize isUnary flag
    }
    toString() {
        return "OP:[" + this.op + (this.isUnary ? "_UNARY" : "") + ":" + this.args.join(", ") + "]";
    }
    precedence()
    {
        if (this.isUnary) {
            if (this.op == "+" || this.op == "-") return 4; // Unary +/- precedence
        }
        // Binary operator precedences
        if (this.op == "+") return 1;
        if (this.op == "-") return 1;
        if (this.op == "*") return 2;
        if (this.op == "/") return 2;
        if (this.op == "^") return 3;
        if (this.op == "**") return 3;
        if (this.op == "=") return 0; // Assignment typically lowest
        throw "unsupported operator: " + this.op;
    }
    add(item) { this.args.push(item); }
};
class Bracket {
    constructor(type) { this.type = type; }
    toString() { return "BRACKET:["+this.type+"]"; }
    isopen() { return "[({<".includes(this.type); }
    isclose() { return "])}>".includes(this.type); }
    closes(t) { return ["[]", "()", "{}", "<>"].includes(t.type+this.type); }
};
class Comma {
    toString() { return "COMMA"; }
};
class Whitespace {
    toString() { return "SPACE"; }
};
class CommentToken {
    constructor(value) { this.value = value; }
    toString() { return "COMMENT:["+this.value+"]"; }
};

function* tokenizer(txt)
{
    var p = 0;
    var patterns = [
        [ CommentToken, /\/\/.*/y ], // Match // comments to end of line
        [ CommentToken, /#.*/y ],    // Match # comments to end of line
        [ NumValue,   /0x[0-9a-fA-F]+\b/y ],
        [ NumValue,   /[0-9]+\b/y ],
        [ Name,       /[a-zA-Z_]\w*(?:\.\w+)*/y ],
        [ Operator,   /\*\*|[=+*/^]|-/y ],
        [ Bracket,    /[()]/y ],
        [ Comma,      /,/y ],
        [ Whitespace, /\s+/y ],
        [ TextValue,  /"[^"]*"/y ],
    ];
    while (p < txt.length)
    {
        var t = null;
        for (var [cls, pattern] of patterns) {
            pattern.lastIndex = p;
            var m = pattern.exec(txt);
            if (m) {
                p = pattern.lastIndex;
                t = new cls(m[0]);
                break;
            }
        }
        if (!t)
            throw "invalid token";
        // Skip yielding comment tokens
        if (!(t instanceof CommentToken)) {
            yield t;
        }
    }
}
class ExpressionList {
    constructor(type, values)
    {
        this.type = type;
        this.values = values;
    }
    toString() { return "EXPR:["+this.type+":"+this.values.join(", ")+"]"; }
};
class Function {
    constructor(name, args)
    {
        this.name = name;
        this.args = args;
    }
    toString() { return "FUNC:["+this.name+":"+this.args.join(", ")+"]"; }
};


function brackets(tokens)
{
    var stack = [];
    var exprlist = [];
    var tokensequence = [];
    for (let t of tokens) {
        if (t instanceof Whitespace)
            continue;
        if (t instanceof Bracket && t.isopen()) {
            stack.push([t, exprlist, tokensequence]);
            exprlist = [];
            tokensequence = [];
        }
        else if (t instanceof Comma) {
            if (stack.length==0)
                throw "comma without bracket";
            exprlist.push(tokensequence);
            tokensequence = [];
        }
        else if (t instanceof Bracket && t.isclose()) {
            exprlist.push(tokensequence);
            let closedlist = exprlist;
            var topen;
            [topen, exprlist, tokensequence] = stack.pop();
            if (!t.closes(topen))
                throw "mismatched brackettypes";
            tokensequence.push(new ExpressionList(topen.type+t.type, closedlist));
        }
        else {
            tokensequence.push(t)
        }
    }
    if (stack.length) {
        throw "unclosed brackets";
    }

    if (tokensequence.length) {
        exprlist.push(tokensequence);
        tokensequence = undefined;
    }

    if (exprlist.length==0)
        return [];

    if (exprlist.length>1)
        throw "expected toplevel exprlist to have just one token sequence";
    return exprlist[0];
}

class EmptyList {
    toString() { return "EMPTY[]"; }
};


function parse(tokens)
{
    /* parse a token stream into an expression tree */
    var stack = [];
    var lastTokenType = null; // null, 'operand', 'operator' (or 'open_bracket' conceptually)

    for (var t of tokens) {
        if (t instanceof ExpressionList) {
            t.values = t.values.map(s => parse(s)); // Recursively parse items in the list
            if (stack.length > 0 && stack[stack.length - 1] instanceof Name) { // Function call: Name(...)
                let funcNameNode = stack.pop();
                t = new Function(funcNameNode.name, t.values);
            }
            stack.push(t);
            lastTokenType = 'operand';
        }
        else if (t instanceof Name || t instanceof NumValue || t instanceof TextValue) {
            stack.push(t);
            lastTokenType = 'operand';
        }
        else if (t instanceof Operator) {
            const isUnaryContext = (lastTokenType === null || lastTokenType === 'operator');

            if ((t.op === '+' || t.op === '-') && isUnaryContext) {
                t.isUnary = true;
                // Push unary operator. It will take its operand during final reduction.
                stack.push(t);
            } else {
                // Binary operator
                t.isUnary = false;
                // Reduce operators on stack with higher/equal precedence than current binary op 't'.
                // This loop assumes operators on stack (stack[len-2]) already have their LHS.
                while (stack.length >= 2 && (stack[stack.length - 2] instanceof Operator) &&
                       !stack[stack.length - 2].isUnary && // Operator on stack must be binary
                       ( ( (stack[stack.length-2].op === '^' || stack[stack.length-2].op === '**') ? t.precedence() < stack[stack.length - 2].precedence() : t.precedence() <= stack[stack.length - 2].precedence() ) )
                      ) {
                    let rhs_for_op_on_stack = stack.pop(); // This is the RHS for operator at stack[len-2]
                    let op_on_stack = stack[stack.length-1]; // This is Op(LHS) at stack[len-2]
                    if (!(op_on_stack instanceof Operator) || op_on_stack.isUnary || op_on_stack.args.length !== 1) {
                         throw "Parser Error: Expected binary operator with 1 arg on stack during precedence reduction.";
                    }
                    op_on_stack.add(rhs_for_op_on_stack);
                    // op_on_stack (which is stack[length-1]) is now Op(LHS,RHS)
                }

                // Current binary operator 't' takes its LHS from the stack.
                if (stack.length === 0 || lastTokenType !== 'operand') {
                     // If stack.length > 0 but lastTokenType != 'operand', it might be an operator.
                     // An operand must precede a binary operator's LHS.
                     // e.g. "5 *", then lastTokenType is 'operand'. If next is "+", valid.
                     // e.g. "* 5", lastTokenType is null or operator. This is an error for binary '*'.
                    throw "Missing left-hand operand for binary operator: " + t.op;
                }
                t.add(stack.pop()); // t gets its LHS
                stack.push(t);      // Push t(LHS)
            }
            lastTokenType = 'operator';
        } else {
            // Should not happen if tokenizer and brackets() are correct
            throw "Unknown token type in parse: " + t.toString();
        }
    }

    // Final reduction loop: combine remaining operators with their arguments.
    // Stack could be [OpUnary, Val] or [OpBinary(LHS), Val_RHS]
    // Or more complex like [Val1, Op1_binary(LHS1), Val2_RHS1_LHS_Op2, Op2_binary(LHS2), Val3_RHS2]
    // The original final loop is:
    // while (stack.length>=2 && stack[stack.length-2] instanceof Operator) {
    //    let rhs = stack.pop();
    //    stack[stack.length-1].add(rhs)
    // }
    // This loop structure assumes that stack[stack.length-1] is the operator
    // (either UnaryOp or BinaryOp_with_LHS) and `rhs` is its argument.

    let i = 0; // Safety break for potentially infinite loop
    while (stack.length > 1 && i < 1000) { // If stack has more than one element, try to reduce
        i++;
        // Peek at top three elements to decide action, common in more complex parsers
        // For this one, assume stack[len-1] is operand, stack[len-2] is operator
        // This is if operators are pushed bare. But they are not for binary ops.
        // Let's use the original loop structure and adapt it.
        let opIndex = -1;
        for (let j = stack.length - 1; j >= 0; j--) {
            if (stack[j] instanceof Operator && ( (stack[j].isUnary && stack[j].args.length === 0) || (!stack[j].isUnary && stack[j].args.length === 1) ) ) {
                opIndex = j;
                break;
            }
        }

        if (opIndex !== -1) {
            let op_to_apply = stack[opIndex];
            if (op_to_apply.isUnary) {
                if (opIndex === stack.length - 1 || op_to_apply.args.length > 0) { // Unary op needs operand after it, or already has it
                     // This means unary op is at end of stack, or already processed.
                     // If it's at end and needs arg, it's an error handled later.
                     // If it has arg, it's fine.
                     // This loop structure is not right for finding specific ops.
                     // Original loop is simpler:
                    if (stack.length < 2) break; // Need op and operand
                     let potential_rhs = stack[stack.length-1];
                     let potential_op = stack[stack.length-2];
                     if (potential_op instanceof Operator) {
                         if (potential_op.isUnary && potential_op.args.length === 0) {
                             potential_op.add(stack.pop()); // Add rhs, op remains at stack[length-1]
                         } else if (!potential_op.isUnary && potential_op.args.length === 1) {
                             potential_op.add(stack.pop()); // Add rhs, op remains at stack[length-1]
                         } else {
                             break; // Operator cannot take this rhs or is malformed
                         }
                     } else {
                         break; // Top is not Op, Operand
                     }

                } else { // Unary op followed by its operand
                    // This case is covered by the above if `potential_op` is `stack[opIndex]`
                    // and `potential_rhs` is `stack[opIndex+1]`.
                    // This requires splicing stack, which is complex.
                    // The original loop `stack[stack.length-1].add(rhs)` is simpler.
                    // It means that `stack[stack.length-1]` IS the operator.
                    // And `rhs = stack.pop()` was the element at `stack.length`.
                    // So stack structure before pop: [..., Op, Rhs]
                    // After pop: [..., Op]. Then Op.add(Rhs).
                    // This is correct.

                    // The condition for the loop `stack.length>=2 && stack[stack.length-2] instanceof Operator`
                    // means stack: [..., Penultimate, Ultimate]. Penultimate is Operator.
                    // This is wrong. stack[length-1] is the operator.
                    // The loop should be:
                    // while (stack.length >= 2 && (stack[stack.length-1] instanceof Operator) && condition_for_op_args )
                    // No, the operator is on the left. [Op, Arg] or [Op(LHS), RHS]
                    // So stack[stack.length-2] is the operator, stack[stack.length-1] is the arg.
                    // This is what the original final loop did.
                    break; // Cannot reduce with this opIndex logic
                }
        } else {
            break; // No suitable operator found to reduce
        }
    }
    if (i >= 1000) console.warn("Parser final reduction loop safety break.");

    // Restore original final loop logic with checks for unary/binary arg counts
    while (stack.length >= 2) {
        let C = stack[stack.length-1]; // Potential RHS or second element of [OpUnary, Arg]
        let B = stack[stack.length-2]; // Potential Operator or first element of [OpUnary, Arg]

        if (B instanceof Operator) {
            if (B.isUnary) {
                if (B.args.length === 0) { // Unary operator expects one argument
                    B.add(C);
                    stack.pop(); // Remove C, B (now B(C)) remains.
                } else break; // Unary op already has its arg, or stack doesn't fit [Op, Arg]
            } else { // B is Binary Operator, expects 2 args. Assumed to have LHS already (B(LHS_B)).
                if (B.args.length === 1) {
                    B.add(C);
                    stack.pop(); // Remove C, B (now B(LHS_B, C)) remains.
                } else break; // Binary op not in state Op(LHS) or stack structure is wrong.
            }
        } else {
            // Stack does not look like [..., Operator, Operand] at the top
            break;
        }
    }


    if (stack.length === 0) return new EmptyList();

    let finalExpr = stack[0];
    if (finalExpr instanceof Operator) {
        if (finalExpr.isUnary && finalExpr.args.length !== 1) {
             throw "Syntax error: Unary operator " + finalExpr.op + " did not receive its operand.";
        }
        if (!finalExpr.isUnary && finalExpr.args.length !== 2) {
             throw "Syntax error: Binary operator " + finalExpr.op + " did not receive all its operands.";
        }
    }
    if (stack.length > 1) { // Should be caught by loop logic or means multiple expressions like "1 2"
        throw "Syntax error: Invalid expression structure, remaining stack: " + stack.map(s=>s.toString()).join('; ');
    }
    return stack.pop();
}

function parseexpr(txt)
{
    return parse(brackets(tokenizer(txt)));
}


function evaluator(e, ctx)
{
    /* evaluate the expression with the specified context. */
    if (e instanceof Operator) {
        if (e.isUnary) {
            if (e.args.length !== 1) throw `Unary operator ${e.op} expects 1 argument, got ${e.args.length}`;
            let val = evaluator(e.args[0], ctx);
            if (e.op === '+') {
                // Unary plus often means Number(val) or just val if already number type
                // Assuming ctx.unary_plus or it's identity for numeric types from context.
                return ctx.unary_plus ? ctx.unary_plus(val) : val;
            }
            if (e.op === '-') {
                // Unary minus means negation.
                // Expects ctx.unary_neg(val) or can simulate with ctx.sub(0, val)
                if (ctx.unary_neg) return ctx.unary_neg(val);
                return ctx.sub(ctx.numbervalue("0"), val); // Default to 0 - val
            }
            throw "unknown unary operator: " + e.op;
        } else {
            // Binary operator logic
            var fn;
            if (e.op == "+") fn = ctx.add;
            else if (e.op == "-") fn = ctx.sub;
            else if (e.op == "*") fn = ctx.mul;
            else if (e.op == "/") fn = ctx.div;
            else if (e.op == "^") fn = ctx.pow;
            else if (e.op == "=") {
                if (e.args.length !== 2) throw `Assignment '=' expects 2 arguments (name, value), got ${e.args.length}`;
                // '=' handles its first argument diffrently (it's a Name, not evaluated yet).
                let varnameNode = e.args[0];
                if (!(varnameNode instanceof Name)) throw "LHS of assignment must be a name.";
                // Evaluate RHS
                let valueToSet = evaluator(e.args[1], ctx);
                ctx.set(varnameNode.name, valueToSet);
                return valueToSet; // Assignment often returns the assigned value
            }
            else {
                throw "unknown binary operator: " + e.op;
            }
            if (e.args.length !== 2) throw `Binary operator ${e.op} expects 2 arguments, got ${e.args.length}`;
            return fn(evaluator(e.args[0], ctx), evaluator(e.args[1], ctx));
        }
    }
    if (e instanceof Function) {
        fn = ctx[e.name];
        return fn(...e.args.map(_=>evaluator(_, ctx)));
    }
    if (e instanceof Name) 
        return ctx.get(e.name);
    if (e instanceof NumValue) 
        return ctx.numbervalue(e.value);
    if (e instanceof TextValue) 
        return ctx.textvalue(e.value);
    if (e instanceof ExpressionList) {
        if (e.values.length==1) 
            return evaluator(e.values[0], ctx);

        // todo, I need a way to propagate a state change in the ctx 
        // when processing values between '()', 
        // example: coordinates in an elliptic curve.
        return ctx.listvalue(e.type, e.values.map(_=>evaluator(_, ctx)));
    }
    if (e instanceof EmptyList)
        return [];
    if (typeof(e) == "array")
        return e.map(_=>evaluator(_, ctx));
    throw "unknown object";
}


