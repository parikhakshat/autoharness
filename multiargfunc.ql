import cpp

Type getParameterTypeElement(Parameter p) {
  result = p.getUnspecifiedType()
  or
  result = getParameterTypeElement(p).(PointerType).getBaseType().getUnspecifiedType()
}

Type getParameterBaseType(Parameter p) {
  result = getParameterTypeElement(p) and not result instanceof PointerType
}

from Function f, Type t, string g, int param_idx
where not exists(Parameter p | p = f.getAParameter() | getParameterBaseType(p) instanceof Struct) and
t = f.getParameter(param_idx).getType() and
g = f.getType().toString()
select f, t, g, param_idx
