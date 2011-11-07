#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wireplay.h>
#include <whook.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <assert.h>
#include <ruby.h>	/* for plugins in Ruby */

static VALUE rb_mWireplay;
static VALUE rb_cHook;

static void rb_w_eval_rbfile(const char *hook_script);

/*
 * UI function
 */
static VALUE rb_w_cmsg(VALUE obj, VALUE str)
{
   StringValue(str);
   cmsg("%s", StringValuePtr(str));

   return Qnil;
}

/*
 * Utility function for converting C datastructure to appropriate Ruby objects
 */

/*
 * Converts a w_hook_desc structure to a Ruby OpenStruct object
 *
 * The returned Ruby object can be access by member variables of exactly same
 * name as defined in w_hook_desc structure
 */
static
VALUE w_hook_desc_to_rb_struct(struct w_hook_desc *w)
{
   VALUE ost_klass;
   VALUE ost_obj;
   int ost_argc = 0;
   VALUE *ost_argv = NULL;
   char *host;

   if(!w) {
      cmsg("WARN: NULL parameter(s) in w_hook_desc_to_rb_struct(..)");
      return Qnil;
   }

   rb_require("ostruct");  /* Comes default with Ruby 1.8.x */

   ost_klass = rb_const_get(rb_cObject, rb_intern("OpenStruct"));
   ost_obj = rb_class_new_instance(ost_argc, ost_argv, ost_klass);

   {
      struct sockaddr_in sin;
      sin.sin_addr.s_addr = w->host;
      host = (char*) inet_ntoa(sin.sin_addr);
   }

   rb_funcall(ost_obj, rb_intern("host="), 1, rb_str_new2(host));
   rb_funcall(ost_obj, rb_intern("port="), 1, INT2FIX(w->port));
   rb_funcall(ost_obj, rb_intern("run_count="), 1, INT2FIX(w->run_count));
   rb_funcall(ost_obj, rb_intern("role="), 1, INT2FIX(w->role));

   return ost_obj;
}

static
VALUE w_hook_data_to_string(const char *data, size_t len)
{
   if(!data)
      return Qnil;
   
   return rb_tainted_str_new(data, len);
}

/*
 * Here begins the Ruby hooker
 */
static void rb_w_event_start(struct w_hook_desc *w)
{
   VALUE hooks;
   VALUE hk;
   int count;

   hk = rb_const_get(rb_mWireplay, rb_intern("Hooks"));
   hooks = rb_funcall(hk, rb_intern("hooks"), 0);

   count = RARRAY(hooks)->len;

   while(count > 0) {
      VALUE obj = rb_ary_entry(hooks, count - 1);
      
      if(rb_obj_respond_to(obj, rb_intern("on_start"), 0))
         rb_funcall(obj, rb_intern("on_start"), 1, w_hook_desc_to_rb_struct(w));
      
      count--;
   }
}

static void rb_w_event_stop(struct w_hook_desc *w)
{
   VALUE hooks;
   VALUE hk;
   int count;

   hk = rb_const_get(rb_mWireplay, rb_intern("Hooks"));
   hooks = rb_funcall(hk, rb_intern("hooks"), 0);

   count = RARRAY(hooks)->len;

   while(count > 0) {
      VALUE obj = rb_ary_entry(hooks, count - 1);
      
      if(rb_obj_respond_to(obj, rb_intern("on_stop"), 0))
         rb_funcall(obj, rb_intern("on_stop"), 1, w_hook_desc_to_rb_struct(w));
      
      count--;
   }

   return;
}

static void rb_w_event_error(struct w_hook_desc *w, int error)
{
   VALUE hooks;
   VALUE hk;
   int count;

   hk = rb_const_get(rb_mWireplay, rb_intern("Hooks"));
   hooks = rb_funcall(hk, rb_intern("hooks"), 0);

   count = RARRAY(hooks)->len;

   while(count > 0) {
      VALUE obj = rb_ary_entry(hooks, count - 1);
      
      if(rb_obj_respond_to(obj, rb_intern("on_error"), 0))
         rb_funcall(obj, rb_intern("on_error"), 2, w_hook_desc_to_rb_struct(w), INT2FIX(error));
      
      count--;
   }

   return;

}

static void 
rb_w_event_data(struct w_hook_desc *w,uint8_t direction, char **data, size_t *len)
{
   VALUE hooks;
   VALUE hk;
   int count;
   VALUE ret;

   if((!data) || (!*data) || (!len)) {
      w_log_printf("RubyHook: Invalid parameters to data event");
      return;
   }

   hk = rb_const_get(rb_mWireplay, rb_intern("Hooks"));
   hooks = rb_funcall(hk, rb_intern("hooks"), 0);

   count = RARRAY(hooks)->len;

   while(count > 0) {
      VALUE obj = rb_ary_entry(hooks, count - 1);
      
      if(rb_obj_respond_to(obj, rb_intern("on_data"), 0)) {
         ret = rb_funcall(obj, rb_intern("on_data"), 3,
                  w_hook_desc_to_rb_struct(w),
                  INT2FIX(direction),
                  rb_str_new(*data, *len));
         /*
          * If ret is a string, then the plugin has modified the data part
          * we must free/alloc/copy data again and change len accordingly
          */
         if(TYPE(ret) == T_STRING) {
            /* TODO: update data and len */
            long rlen = RSTRING(ret)->len;
            
            free(*data);
            *data = malloc(rlen + 1);
            assert(*data != NULL);

            memcpy(*data, StringValuePtr(ret), rlen);
            *len = rlen;
         }
      }
      
      count--;
   }

   return;
}

static VALUE
rb_cHook_register(VALUE klass, VALUE hook)
{
   VALUE ary;

   if(!NIL_P(hook)) {
      ary = rb_cvar_get(klass, rb_intern("_hooks"));
      rb_ary_push(ary, hook);
   }

   return hook;
}

static VALUE rb_cHook_hooks(VALUE klass)
{
   return rb_cvar_get(klass, rb_intern("_hooks"));
}

static VALUE rb_mWireplay_load_library(VALUE klass, VALUE rblib)
{
   char *libpath = NULL;
   char *rblib_path;
	char *rblib_dir = "/rblib/";
	struct stat st;
   VALUE ret = Qnil;

   w_get_lib_path(&libpath);
   assert(libpath != NULL);

   StringValue(rblib);
   rblib_path = malloc(strlen(libpath) + strlen(StringValuePtr(rblib)) + strlen(rblib_dir) + 1);
   assert(rblib_path != NULL);
   
   /*
    * Really, I don't carry if you /../ here
    */
   strcpy(rblib_path, libpath);
   strcpy(rblib_path + strlen(libpath), rblib_dir);
   strcpy(rblib_path + strlen(libpath) + strlen(rblib_dir), StringValuePtr(rblib));

	if(stat(rblib_path, &st) == -1)
		cmsg("WARN: Attempting to evaluate non-existent file (%s)", rblib_path);

   rb_w_eval_rbfile(rblib_path);

   free(rblib_path);
   free(libpath);

   return ret;
}

static VALUE rb_test_start_irb(VALUE klass)
{
   VALUE irb_klass;
   VALUE __file__;

   rb_require("irb");   /* must have irb installed */
   irb_klass = rb_const_get(rb_cObject, rb_intern("IRB"));

   return rb_funcall(irb_klass, rb_intern("start"), 1, Qnil);
}

static void rb_w_define_klass()
{
   /*
    * Initialize Ruby Interpreter
    */
   int rb_argc = 0;
   char *rb_argv[] = {NULL};

   ruby_init();
   ruby_init_loadpath();
   ruby_options(rb_argc, rb_argv);
   ruby_script("Wireplay");
   /*
    * Initialize the Wireplay::Hook class for ruby hook repository
    */
   rb_mWireplay = rb_define_module("Wireplay");
   
   rb_const_set(rb_mWireplay, rb_intern("WIREPLAY_PROG_NAME"), rb_str_new2(WIREPLAY_PROG_NAME));
   rb_const_set(rb_mWireplay, rb_intern("WIREPLAY_PROG_VER"), rb_str_new2(WIREPLAY_PROG_VER));
   //rb_const_set(rb_mWireplay, rb_intern("WIREPLAY_AUTHOR"), rb_str_new2(WIREPLAY_AUTHOR));
   rb_const_set(rb_mWireplay, rb_intern("WIREPLAY_COPYRIGHT"), rb_str_new2(WIREPLAY_COPYRIGHT));

   rb_const_set(rb_mWireplay, rb_intern("REPLAY_SERVER_TO_CLIENT"), INT2FIX(REPLAY_SERVER_TO_CLIENT));
   rb_const_set(rb_mWireplay, rb_intern("REPLAY_CLIENT_TO_SERVER"), INT2FIX(REPLAY_CLIENT_TO_SERVER));

   rb_const_set(rb_mWireplay, rb_intern("ERROR_CONNECT_FAILED"), INT2FIX(ERROR_CONNECT_FAILED));
   rb_const_set(rb_mWireplay, rb_intern("ERROR_SEND_FAILED"), INT2FIX(ERROR_SEND_FAILED));
   rb_const_set(rb_mWireplay, rb_intern("ERROR_RECV_FAILED"), INT2FIX(ERROR_RECV_FAILED));
   rb_const_set(rb_mWireplay, rb_intern("ERROR_TIMEOUT"), INT2FIX(ERROR_TIMEOUT));
   rb_const_set(rb_mWireplay, rb_intern("ERROR_SOCKET_ERROR"), INT2FIX(ERROR_SOCKET_ERROR));

   rb_const_set(rb_mWireplay, rb_intern("ROLE_CLIENT"), INT2FIX(ROLE_CLIENT));
   rb_const_set(rb_mWireplay, rb_intern("ROLE_SERVER"), INT2FIX(ROLE_SERVER));

   rb_define_global_function("cmsg", rb_w_cmsg, 1);
   /* TODO: define other msg.c functions */

   rb_cHook = rb_define_class_under(rb_mWireplay, "Hooks", rb_cObject);
   rb_cvar_set(rb_cHook, rb_intern("_hooks"), rb_ary_new(), 0);
   rb_define_singleton_method(rb_cHook, "register", rb_cHook_register, 1);
   rb_define_singleton_method(rb_cHook, "hooks", rb_cHook_hooks, 0);

   rb_define_singleton_method(rb_mWireplay, "start_irb", rb_test_start_irb, 0);
   rb_define_singleton_method(rb_mWireplay, "load_library", rb_mWireplay_load_library, 1);
   
   //rb_test_start_irb();
	return;
}

static void rb_w_eval_plugins()
{
   char *hook_script;

   hook_script = (char*) w_hook_get_file();

   if(!hook_script) {
      w_log_printf("RubyHook: No script to evaluate");
      return;
   }
   
   rb_w_eval_rbfile(hook_script);
}

static void rb_w_eval_rbfile(const char *hook_script)
{
   char *buf;
   struct stat st;
   int ret;
   int fd;
   int n, c;

   w_log_printf("RubyHook: Evaluating script file at %s", hook_script);

   ret = stat(hook_script, &st);
   if((ret == -1) || (!S_ISREG(st.st_mode))) {
      w_log_printf("RubyHook: Script file not found or invalid");
      return;
   }

   buf = malloc(st.st_size + 1);
   assert(buf != NULL);

   fd = open(hook_script, O_RDONLY);
   assert(fd != -1);
   
   n = st.st_size;
   c = 0;
   while(n > 0) {
      ret = read(fd, buf + c, n);

      if(ret < 0)
         cfatal("RubyHook: Plugin script read loop failed");

      n -= ret;
      c += ret;
   }
   close(fd);

   rb_eval_string(buf);
   free(buf);
}

static void rb_w_hook_init(struct w_hook_conf *whc)
{
	rb_w_define_klass();
	rb_w_eval_plugins();
}

static void rb_w_hook_deinit()
{
	return;
}

static
struct w_hook rb_hook = {
	.name		= "ruby",
	.init		= rb_w_hook_init,
   .start   = rb_w_event_start,
   .data    = rb_w_event_data,
   .stop    = rb_w_event_stop,
   .error   = rb_w_event_error,
	.deinit	= rb_w_hook_deinit
};

static
struct w_hook_conf rb_hook_conf = {
	.search_path 	= NULL,  /* unused */
	.ext				= NULL   /* unused */
};

int w_rbhook_init()
{
   cmsg("Initializing Ruby hook (Hook File: %s)", w_hook_get_file());
   w_register_hook(&rb_hook, &rb_hook_conf);
}

void w_rbhook_deinit()
{
   return;
}
