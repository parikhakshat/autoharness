import cpp

from Function f, Variable v, string s, string g
where
	f.getNumberOfParameters() = 1 and
	v = f.getParameter(0) and
	not (v.getUnspecifiedType() instanceof Struct) and
	not (v.getUnspecifiedType().(PointerType).getBaseType+().getUnspecifiedType() instanceof Struct) and
	s = v.getUnspecifiedType().toString() and
	s != "..(*)(..)" and
	g = f.getType().toString()
select f, s, g
