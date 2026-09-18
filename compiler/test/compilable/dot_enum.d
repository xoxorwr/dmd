// Leading-dot enum member lookup: `.member` is resolved against the target
// type inferred from the surrounding context, in addition to the usual module
// scope lookup. This allows writing `.red` instead of `Color.red` whenever the
// expected type is known.

enum Color { red, green, blue }
enum Flags : int { a = 1, b = 2, c = 4 }
enum { topLevelA = 10, topLevelB }

struct Pixel
{
    Color color;
    int x;
}

Color makeColor() { return .green; }
void takeColor(Color c) {}
void takeTwo(Color a, Color b) {}
void defaultColor(Color c = .red) {}

void main()
{
    // variable initializer and assignment
    Color c = .red;
    c = .blue;

    // const and immutable
    const Color cc = .green;
    immutable Color ic = .red;

    // function arguments, including several parameters
    takeColor(.red);
    takeTwo(.green, .blue);
    takeTwo(.red, .blue);

    // return statements and default parameters
    Color r = makeColor();
    defaultColor();
    defaultColor(.green);

    // struct literal fields
    Pixel p = Pixel(.red, 3);

    // dynamic array literal elements
    Color[] arr = [.red, .green, .blue];

    // bitwise operators
    Flags f = .a | .b;
    Flags g = .a | .b | .c;

    // conditional expression with a known target type
    bool pick = true;
    Color t = pick ? .red : .green;

    // switch case labels
    switch (c)
    {
        case .red: break;
        case .green: break;
        case .blue: break;
        default: break;
    }

    // leading dot for module-scope anonymous enum members still works
    int top = .topLevelA;
    int top2 = .topLevelB;
}
