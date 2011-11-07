class MySampleHook
   def initialize
      puts ">> MySampleHook initialized"
   end

   def on_start(desc)
      puts ">> MySampleHook start (desc: #{desc.inspect})"
   end

   def on_data(desc, direction, data)
      puts ">> MySampleHook data (desc: #{desc.inspect})"
      puts ">> MySampleHook data (direction: #{direction})"
      puts ">> MySampleHook data (data size: #{data.size})"
   end

   def on_stop(desc)
      puts ">> MySampleHook stop (desc: #{desc.inspect})"
   end
end

Wireplay::Hooks.register(MySampleHook.new)
