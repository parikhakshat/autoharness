import cpp

from Function f, Variable v, string t, string g
where
	f.getNumberOfParameters() = 1 and
	v = f.getParameter(0) and
	not (v.getUnspecifiedType() instanceof Struct) and
	not (v.getUnspecifiedType().(PointerType).getBaseType+().getUnspecifiedType() instanceof Struct) and
	t = v.getUnspecifiedType().toString() and
	t != "..(*)(..)" and
	g = f.getType().toString()
select f, t, g