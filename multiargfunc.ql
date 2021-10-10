import cpp

Type getParameterTypeElement(Parameter p) {
  result = p.getUnspecifiedType()
  or
  result = getParameterTypeElement(p).(PointerType).getBaseType().getUnspecifiedType()
}

Type getParameterBaseType(Parameter p) {
  result = getParameterTypeElement(p) and not result instanceof PointerType
}

from Function f, Type t, string g 
where not exists(Parameter p | p = f.getAParameter() | getParameterBaseType(p) instanceof Struct) and
t = f.getAParameter().getType() and
g = f.getType().toString()
select f, t, g
