class A
  def last; end # trailing
end
module B
  def a; end # trailing
  def last; end # trailing
end
def f
  def only; end # trailing
end
if true
  def only; end # trailing
end
1.times do
  def only; end # trailing
end
class Wrapper
  private def wrapped; end; def after; end # trailing
end
def top; end # trailing
# next comment
