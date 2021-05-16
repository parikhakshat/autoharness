import cpp

from Function f, Variable v, string s, string l
where 
	not exists(FunctionCall fc | fc.getTarget() = f) and
	f.getNumberOfParameters() = 1 and
	v = f.getParameter(0) and
	not (v.getUnspecifiedType() instanceof Struct) and
	not (v.getUnspecifiedType().(PointerType).getBaseType+().getUnspecifiedType() instanceof Struct) and
	s = v.getUnspecifiedType().toString() and
	s != "..(*)(..)" and
	l = f.getADeclarationLocation().getContainer().getParentContainer().toString()
select f, s, l
