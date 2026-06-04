from django import template

register = template.Library()


@register.filter
def abs_value(value):
    try:
        return abs(int(value))
    except (ValueError, TypeError):
        return value


@register.filter
def get_attr(obj, attr_name):
    return getattr(obj, attr_name, False)
