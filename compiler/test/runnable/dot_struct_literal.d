// PERMUTE_ARGS:

// Runtime behavior of the context-sensitive aggregate literal `.{...}`, where
// the struct type is inferred from the surrounding context.

struct Vec2 { float x; float y; }
struct State { Vec2 pos; }
struct Outer { Vec2 a; Vec2 b; }

Vec2 makeVec() { return .{1.0, 2.0}; }

void takeVec(Vec2 v) {}

void main()
{
    // initializer / assignment
    Vec2 v = .{1.0, 2.0};
    assert(v.x == 1.0 && v.y == 2.0);
    v = .{3.0, 4.0};
    assert(v.x == 3.0 && v.y == 4.0);

    // const / immutable
    const Vec2 cv = .{1.0, 2.0};
    assert(cv.x == 1.0 && cv.y == 2.0);
    immutable Vec2 iv = .{3.0, 4.0};
    assert(iv.x == 3.0 && iv.y == 4.0);

    // return statement
    Vec2 r = makeVec();
    assert(r.x == 1.0 && r.y == 2.0);

    // struct field assignment
    State s;
    s.pos = .{5.0, 6.0};
    assert(s.pos.x == 5.0 && s.pos.y == 6.0);

    // named arguments
    Vec2 named = .{y: 8.0, x: 7.0};
    assert(named.x == 7.0 && named.y == 8.0);

    // nested
    Outer o = .{.{1.0, 2.0}, .{3.0, 4.0}};
    assert(o.a.x == 1.0 && o.a.y == 2.0);
    assert(o.b.x == 3.0 && o.b.y == 4.0);

    // empty / partial
    Vec2 bempty = .{};
    assert(bempty.x == 0.0 && bempty.y == 0.0);
    Vec2 bpartial = .{7.0};
    assert(bpartial.x == 7.0 && bpartial.y == 0.0);

    // function argument
    takeVec(.{8.0, 9.0});
}
