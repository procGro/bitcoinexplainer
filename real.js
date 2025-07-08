/* Author: Willem Hengeveld <itsme@xs4all.nl> */
/* https://github.com/nlitsme/bitcoinexplainer */
"use strict";

/* real number arithmetic */

function numequals(a, b)
{
    return Math.abs(a-b) < 0.0001;
}
function realval(x)
{
    if (x instanceof RealValue) { return x.real(); }
    return x;
}
/* this class represents a real value */
class RealValue {
    constructor(field, num)
    {
        this.field = field;
        this.num = num;
    }
    add(rhs) { return this.field.add(this, rhs); }
    double() { return this.field.add(this, this); }
    thrice() { return this.field.add(this.double(), this); }
    sub(rhs) { return this.field.sub(this, rhs); }
    mul(rhs) { return this.field.mul(this, rhs); }
    square() { return this.field.mul(this, this); }
    cube() { return this.field.mul(this.square(), this); }
    div(rhs) { return this.field.div(this, rhs); }
    pow(rhs) { return this.field.pow(this, rhs); }
    sqrt(n) { return this.field.sqrt(this, n); }
    cubert(n) { return this.field.cubert(this, n); }
    neg() { return this.field.neg(this); }
    inverse() { return this.field.inverse(this); }
    iszero() { return this.field.iszero(this); }
    equals(rhs) { return this.field.equals(this, rhs); }

    shr() { return this.field.shr(this); }

    real() { return this.num; }

    toString() { return this.num.toFixed(8); }
};

/* this class represents the real numbers */
class RealNumbers {
    constructor() {  }
    toString() {
        return "real";
    }

    value(x)
    {
        // force x to be a real number.
        return new RealValue(this, realval(x));
    }
    add(lhs, rhs) { this.checkfields(lhs, rhs); return this.value(realval(lhs)+realval(rhs)); }
    sub(lhs, rhs) { this.checkfields(lhs, rhs); return this.value(realval(lhs)-realval(rhs)); }
    neg(a) { return this.value(-realval(a)); }
    mul(lhs, rhs) { this.checkfields(lhs, rhs); return this.value(realval(lhs)*realval(rhs)); }
    inverse(a) { return realval(a) ? this.value( 1 / realval(a)) : Infinity; }
    div(lhs, rhs) { this.checkfields(lhs, rhs); return this.mul(lhs, rhs.inverse()); }
    pow(lhs, rhs) { return this.value(realval(lhs) ** realval(rhs)); }

    checkfields() {
        return true;
    }

    sqrt(a, n)
    {
        return this.value(n ? -Math.sqrt(a.real()) : Math.sqrt(a.real()));
    }
    cubert(a, n)
    {
        return this.value(a.real()**(1/3));
    }

    /**
     * Calculates the natural logarithm (base e).
     * @param {RealValue|number} a - The value.
     * @returns {RealValue} The natural logarithm of a.
     */
    ln(a) {
        return this.value(Math.log(realval(a)));
    }

    /**
     * Calculates the base-10 logarithm.
     * @param {RealValue|number} a - The value.
     * @returns {RealValue} The base-10 logarithm of a.
     */
    log10(a) {
        return this.value(Math.log10(realval(a)));
    }

    /**
     * Calculates the base-2 logarithm.
     * @param {RealValue|number} a - The value.
     * @returns {RealValue} The base-2 logarithm of a.
     */
    log2(a) {
        return this.value(Math.log2(realval(a)));
    }

    /**
     * Calculates the logarithm of a with a specified base.
     * @param {RealValue|number} base - The base of the logarithm.
     * @param {RealValue|number} a - The value.
     * @returns {RealValue} The logarithm of a with the given base.
     */
    log(base, a) {
        const rbase = realval(base);
        const ra = realval(a);
        if (rbase <= 0 || rbase === 1) {
            return this.value(NaN); // Invalid base
        }
        return this.value(Math.log(ra) / Math.log(rbase));
    }

    zero() { return 0.0; }
    iszero(x) { return Math.abs(realval(x)) < 0.0001; }

    equals(lhs, rhs) { this.checkfields(lhs, rhs); return lhs.sub(rhs).iszero(); }
    shr(x) { 
        var [bit, res] = numshr(realval(x));
        return [bit, this.value(res)];
    }

    equalsfield(f)
    {
        return true;
    }
};
