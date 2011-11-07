# Blind data stream fuzzer

class StreamFuzzer
   def initialize
      @started = false
      @saveslot = []
      @pkt_count = 0
   end

   def on_start(w_desc)
      @started = true
      @fuzz_state = 0
      @curr_state = 0

      if w_desc.run_count > 1
         @fuzz_state = 1 + (rand(Process.pid) % (@pkt_count - 1))
      end

      cmsg("StreamFuzzer: Received start event (fuzz state: #{@fuzz_state})")
   end

   def on_stop(w_desc)
      @started = false

      cmsg("StreamFuzzer: Received stop event")
   end

   def on_data(w_desc, direction, data)
      unless @started
         cmsg("StreamFuzzer: Not in started state")
         return nil
      end

      unless (direction == Wireplay::REPLAY_CLIENT_TO_SERVER)
         return nil
      end

      if w_desc.run_count == 1
         # During the first run, we just count the no. of packets we are sending
         # to the server. From next run onwards, we just select one of the
         # packet to fuzz, we dont fuzz all the packets because in that case it
         # won't hit all the code
         @pkt_count += 1
         return nil
      end

      if @curr_state == @fuzz_state
         @curr_state += 1
         return do_stream_fuzz(data)
      else
         @curr_state += 1
         return data
      end

      nil
   end

   def on_error(w_desc, error)
      cmsg("StreamFuzzer: Received error event (code: #{error})")
   end

   private
   def do_stream_fuzz(data)
      data = data.dup
      lower_bound = 0
      upper_bound = data.size
      
      count = 1 + (rand(Process.pid) % 10)

      count.times do
         selection = lower_bound + (rand(Process.pid) % upper_bound)
         byte = data[selection]
         byte = (byte | (1 << (rand(Process.pid) % 8)))
         data[selection] = byte
      end

      return data
   end

   def set_last_buffer(data)
      if @saveslot.size >= 5
         @saveslot.shift
      end

      @saveslot.push(data)
   end
end

Wireplay::Hooks.register(StreamFuzzer.new)
