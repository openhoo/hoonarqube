class C {
  _x: number = 2;
  get x(): number {
    return this._y;
  }
}
const o = {
  w_: 'blah',
  set w(value) {
    this.other = value;
  },
};
