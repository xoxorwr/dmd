// Context-sensitive aggregate literal `.{...}`: the struct type is inferred
// from the surrounding context, analogous to the leading-dot enum lookup
// (`.member`). This allows writing `.{...}` instead of `Type(...)` whenever the
// expected type is known.

struct Vec2 { float x; float y; }
struct State { Vec2 pos; }
struct Outer { Vec2 a; Vec2 b; }

Vec2 makeVec() { return .{1.0, 2.0}; }
void takeVec(Vec2 v) {}
void takeTwo(Vec2 a, Vec2 b) {}
void defaultVec(Vec2 v = .{1.0, 2.0}) {}

void main()
{
    // variable initializer and assignment
    Vec2 v = .{1.0, 2.0};
    v = .{3.0, 4.0};

    // const and immutable
    const Vec2 cv = .{1.0, 2.0};
    immutable Vec2 iv = .{3.0, 4.0};

    // function arguments
    takeVec(.{5.0, 6.0});
    takeTwo(.{1.0, 2.0}, .{3.0, 4.0});
    defaultVec();
    defaultVec(.{7.0, 8.0});

    // return statement
    Vec2 r = makeVec();

    // struct field assignment and initialization
    State state;
    state.pos = .{9.0, 10.0};
    State state2 = .{.{11.0, 12.0}};

    // named arguments
    Vec2 named = .{x: 13.0, y: 14.0};

    // nested aggregate literals
    Outer o = .{.{1.0, 2.0}, .{3.0, 4.0}};

    // empty argument list
    Vec2 empty = .{};

    // partial (remaining fields default)
    Vec2 partial = .{15.0};
}
