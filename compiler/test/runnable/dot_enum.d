// PERMUTE_ARGS:

// Runtime behavior of leading-dot enum member lookup (`.member`), where the
// enum type is inferred from the surrounding context.

enum Color { red, green, blue }
enum State : int { off, on }
enum Flags : int { a = 1, b = 2, c = 4 }

struct Pixel
{
    Color color;
    int x;
}

void takeColor(Color c)
{
    assert(c == Color.red);
}

Color pick(bool b)
{
    return b ? .red : .green;
}

void main()
{
    // initializer / assignment
    Color c = .green;
    assert(c == Color.green);
    c = .blue;
    assert(c == Color.blue);

    // const / immutable
    const Color cc = .red;
    assert(cc == Color.red);
    immutable Color ic = .green;
    assert(ic == Color.green);

    // function argument
    takeColor(.red);

    // return statement and conditional
    assert(pick(true) == Color.red);
    assert(pick(false) == Color.green);

    // struct literal
    Pixel p = Pixel(.red, 7);
    assert(p.color == Color.red);
    assert(p.x == 7);

    // dynamic array literal
    Color[] arr = [.red, .green, .blue];
    assert(arr.length == 3);
    assert(arr[0] == Color.red);
    assert(arr[1] == Color.green);
    assert(arr[2] == Color.blue);

    // explicit enum base type
    State s = .on;
    assert(s == State.on);

    // bitwise operators
    Flags f = .a | .b;
    assert(f == (Flags.a | Flags.b));
    Flags g = .a | .b | .c;
    assert(g == (Flags.a | Flags.b | Flags.c));

    // switch case labels
    switch (c)
    {
        case .red: assert(false); break;
        case .green: assert(false); break;
        case .blue: break;
        default: assert(false); break;
    }
}
