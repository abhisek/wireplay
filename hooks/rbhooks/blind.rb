module Attack
 class StringAttack
   attr_accessor :string 
   def initialize(string)
     @string = string
   end 
   def AppendStringAfterEachByte(repeat_string,no_of_repetation)  
     ret_array = []
     for i in 0...@string.length 
        ret_str = String.new(@string)
        first_part = ret_str[0,i+1]
        last_part  = ret_str[i+1,ret_str.length]
        ret_str = first_part
        ret_str = ret_str + ( repeat_string * no_of_repetation )       
        ret_str = ret_str + last_part
        ret_array << ret_str
     end
     return ret_array
   end
   def ReplaceEachCharacterByOther(replace_ch_val)
     ret_array = []
     for i in 0...@string.length 
        ret_str = String.new(@string)
        ret_str[i] = replace_ch_val
        ret_array << ret_str
     end
     return ret_array
   end
   def Replay(n_bytes)
     ret_array = []
     for i in 0...@string.length
        ret_str = String.new(@string)
        first_part = ret_str[0,i+1]
        last_part  = ret_str[i+1,ret_str.length]
        if ( i-n_bytes > 0 ) 
          last_n_part = ret_str[i-n_bytes,i]
        else
          last_n_part = ret_str[0,i]
        end
        ret_str = first_part
        ret_str = ret_str + last_n_part
        ret_str = ret_str + last_part
        ret_array << ret_str
     end
     return ret_array
   end
 end
end

class BlindFuzzer
   def initialize
      @learned = false
      @packets = []
      @procs = []

      @packet_idx = 0
      @data_idx = 0

      @current_packet_idx = 0
      @current_data_idx = 0
   end

   def on_start(desc)
      cmsg("BlindFuzzer: Received start..")

      @current_packet_idx = 0
      @current_data_idx = 0
   end

   def on_stop(desc)
      cmsg("BlindFuzzer: Received stop..")

      unless @learned
         cmsg("BlindFuzzer: Learning finished..")
         cmsg("BlindFuzzer: Total Replayable packets: #{@packets.size}")

         do_prepare()

         cnt = 0
         @procs.each {|p| cnt += p.size}
         cmsg("BlindFuzzer: Total Fuzz procs: #{cnt}")
         @learned = true
      else
         if @packet_idx >= @procs.size
            cmsg("BlindFuzzer: No more cases to test")
            return nil
         end

         if @data_idx >= @procs[@packet_idx].size
            @data_idx = 0
            @packet_idx += 1
         else
            @data_idx += 1
         end
      end
   end

   def on_error(desc, code)
      cmsg("BlindFuzzer: Received error (code: #{code})..")

      unless @learned
         cmsg("BlindFuzzer: Error occurred before learning, NOT A GOOD SIGN")
      end
   end

   def on_data(desc, direction, data)
      begin
         _on_data(desc, direction, data)
      rescue ::Exception => e
         cmsg("BlindFuzzer: Exception (#{e.message})")
         nil
      end
   end

   def _on_data(desc, direction, data)
      unless @learned
         do_learn(desc, direction, data)
         return nil
      end

      unless fuzzable?(desc, direction)
         return nil
      end

      if @packet_idx >= @procs.size
         cmsg("BlindFuzzer: No more cases to test")
         return nil
      end

      if @current_packet_idx != @packet_idx
         @current_packet_idx += 1
         return nil
      end
      
      @current_packet_idx += 1
      cmsg("BlindFuzzer: packet_idx=#{@packet_idx} data_idx=#{@data_idx}")
      return @procs[@packet_idx][@data_idx]
   end

   def fuzzable?(desc, direction)
      case desc.role
         when Wireplay::ROLE_SERVER
            return true if direction == Wireplay::REPLAY_SERVER_TO_CLIENT
         when Wireplay::ROLE_CLIENT
            return true if direction == Wireplay::REPLAY_CLIENT_TO_SERVER
         else
            cmsg("BlindFuzzer: Invalid role")
      end

      false
   end

   def do_learn(desc, direction, data)
      case desc.role
         when Wireplay::ROLE_SERVER
            @packets << data if direction == Wireplay::REPLAY_SERVER_TO_CLIENT
         when Wireplay::ROLE_CLIENT
            @packets << data if direction == Wireplay::REPLAY_CLIENT_TO_SERVER
         else
            cmsg("BlindFuzzer: Invalid role")
      end
   end

   def do_prepare
      if @packets.empty?
         cmsg("BlindFuzzer: huh? Nothing to prepare")
         return nil
      end
      
      idx = 0
      @packets.each do |data|
         procs = do_prepare_data(data)
         @procs[idx] ||= []
         @procs[idx] += procs
         idx += 1
      end
   end

   def do_prepare_data(data)
      procs = []
      at = Attack::StringAttack.new("")
      
      at.string = data
      procs += at.AppendStringAfterEachByte("A", 512)
      procs += at.AppendStringAfterEachByte("\\..\\", 2048)
      procs += at.AppendStringAfterEachByte("X", 4096)
      procs += at.AppendStringAfterEachByte("X", 40960)
      procs += at.AppendStringAfterEachByte("%n", 100)

      procs += at.ReplaceEachCharacterByOther("\xff")
      procs += at.ReplaceEachCharacterByOther("\xfe")
      procs += at.ReplaceEachCharacterByOther("\x00")
      procs += at.ReplaceEachCharacterByOther("\x01")
      procs += at.ReplaceEachCharacterByOther("\x80")

      return procs
   end
end

Wireplay::Hooks.register(BlindFuzzer.new)
