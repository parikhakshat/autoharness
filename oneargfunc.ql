import cpp

from Function f, Variable v, string x, string t, string g
where
	f.getNumberOfParameters() = 1 and
	v = f.getParameter(0) and
	not (v.getUnspecifiedType() instanceof Struct) and
	not (v.getUnspecifiedType().(PointerType).getBaseType+().getUnspecifiedType() instanceof Struct) and
	x = v.getUnspecifiedType().toString() and
	x != "..(*)(..)" and
	g = f.getType().toString() and
	t = v.getType().toString()
select f, t, g
