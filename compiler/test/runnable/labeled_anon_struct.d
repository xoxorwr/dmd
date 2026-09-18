// PERMUTE_ARGS:

// Runtime behavior of C-style labeled anonymous structs/unions: a declarator
// after an anonymous aggregate introduces one member of the synthetic type.

struct Point
{
    struct
    {
        long x;
        long y;
    } pos;
}

struct Rect
{
    struct { int x; int y; } topLeft;
    struct { int w; int h; } size;
    int id;
}

union Value
{
    union
    {
        uint bits;
        float f;
    } raw;
}

struct Holder
{
    struct { int a; } first, second;
    struct { int b; } init = { 9 };
    struct
    {
        struct { int deep; } inner;
    } mid;
}

void main()
{
    Point p;
    p.pos.x = 3;
    p.pos.y = -4;
    assert(p.pos.x == 3);
    assert(p.pos.y == -4);
    assert(Point.pos.sizeof == 2 * long.sizeof);

    Rect r;
    r.topLeft.x = 1;
    r.topLeft.y = 2;
    r.size.w = 5;
    r.size.h = 6;
    r.id = 7;
    assert(r.topLeft.x == 1 && r.topLeft.y == 2);
    assert(r.size.w == 5 && r.size.h == 6);
    assert(r.id == 7);

    // distinct anonymous structs get distinct synthetic types
    r.topLeft.x = 11;
    r.size.w = 22;
    assert(r.topLeft.x == 11);
    assert(r.size.w == 22);

    // overlapping union members
    Value v;
    v.raw.f = 1.0f;
    assert(v.raw.bits == 0x3F80_0000);
    v.raw.bits = 0x4000_0000;
    assert(v.raw.f == 2.0f);

    Holder h;
    h.first.a = 1;
    h.second.a = 2;
    assert(h.first.a == 1);
    assert(h.second.a == 2);
    assert(h.init.b == 9);
    h.init.b = 10;
    assert(h.init.b == 10);
    h.mid.inner.deep = 12;
    assert(h.mid.inner.deep == 12);
}
