// A C-style anonymous struct/union can carry a declarator, introducing a
// single named member whose type is the synthetic aggregate. Without a
// declarator the members are still injected into the enclosing aggregate as
// before.

// module-scope labeled anonymous struct and union
struct { int x; int y; } globalPoint;
union { int i; float f; } globalValue;

struct Point
{
    struct
    {
        int x;
        int y;
    } pos;
}

union Value
{
    union
    {
        int i;
        float f;
    } raw;
}

struct Holder
{
    // several declarators share one synthetic type
    struct { int a; } first, second;

    // pointer declarator
    struct { int b; }* ptr;

    // initializer
    struct { int c; } init = { 5 };

    // storage classes and alignment apply to the synthetic type
    const struct { int d; } cd;
    immutable struct { int e; } ie;
    align(16) struct { int f; int g; } aligned;

    // nested labeled anonymous aggregates
    struct
    {
        struct { int deep; } inner;
    } mid;

    // unlabeled anonymous struct: members are injected
    struct { int injected; }
}

void main()
{
    globalPoint.x = 1;
    globalPoint.y = 2;
    globalValue.i = 3;

    Point p;
    p.pos.x = 1;
    p.pos.y = 2;

    Value v;
    v.raw.i = 3;

    Holder h;
    h.first.a = 1;
    h.second.a = 2;
    h.ptr = null;
    h.init.c = 3;
    h.aligned.f = 4;
    h.aligned.g = 5;
    h.mid.inner.deep = 6;
    h.injected = 7;

    const int d = h.cd.d;
    immutable int e = h.ie.e;
}

static assert(Holder.aligned.alignof == 16);
