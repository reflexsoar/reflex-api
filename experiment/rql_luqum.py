from luqum.parser import parser

tree = parser.parse('(title: "Test Event" and description:"Awesome") OR title: "Smaller Test Event"')
print(repr(tree))