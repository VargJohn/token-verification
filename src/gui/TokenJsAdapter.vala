/* application.vala
 *
 * Copyright 2023 varghese
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */


namespace Tokenverification {
    public class TokenJsAdapter :Gtk.Window {
        private int txn_id;
        private WebKit.WebView web_view;
        private string authorization_code;
        public string token;
        private Gtk.Window web_view_window;
        public bool authentication_done;
        private WebKit.CookieManager cookie_mgr;
        private string state;
        private WebKit.UserContentManager content_manager;

        public TokenJsAdapter () {
            Object ();
            txn_id = 0;
            authorization_code = "";
            token = "";
            state = "";
            init ();
        }

        public bool init (Cancellable? cancellable = null) {
            try {
		        web_view = new WebKit.WebView ();
		    	web_view_window = new Gtk.Window();
              	web_view_window.add(web_view);

                /* Connecting to signal from webview */
                web_view.load_changed.connect ((view, event) => {
                    var prov_uri = view.get_uri();
                    var event_name = ((EnumClass) typeof (WebKit.LoadEvent).class_ref ()).get_value (event).value_name;
                    stdout.printf ("Received event(%s) from WebView\n", event_name);
                    stdout.printf ("Received event(%s) from WebView\n", prov_uri);
                    return;
                });

				string[] cors_list = {"*::/*/*"};
		        WebKit.Settings *settings = web_view.get_settings();
		        web_view.set_cors_allowlist (cors_list);
            	settings->enable_javascript = true;
            	settings->enable_write_console_messages_to_stdout = true;
				cookie_mgr = web_view.web_context.get_website_data_manager().get_cookie_manager ();
				content_manager = web_view.get_user_content_manager ();
				content_manager.script_message_received.connect ((js_result) =>
				{
				    token = js_result.get_js_value ().to_string ();
    				stdout.printf ("Test result: App Token=> %s", token);
    				authentication_done = true;
    			});
				if (!content_manager.register_script_message_handler ("appToken"))
    				stdout.printf ("Failed to register script message handler");

            } catch (Error e) {
                stderr.printf ("%s\n", e.message);
            }

            return true;
        }

        public async bool token_js_adapter_get_authorization_code (
        						Cancellable? cancellable = null) {
            if (cancellable == null || (!cancellable.is_cancelled())){
            	try {
                    uint8[] contents;
                    string etag_out;

            		var file = File.new_for_path ("../../src/gui/tokensso.html");
            		if (!file.query_exists ()) {
                		stderr.printf ("File '%s' doesn't exist.\n", file.get_path ());
                		assert_false (false);
                		return false;
            		}
            		file.load_contents (null, out contents, out etag_out);
            		//var html_code = (string) contents;
            		//web_view.load_html(html_code, null);
					var bytes_code = new Bytes(contents);
            		web_view.load_bytes(bytes_code, null, null, null);
            		web_view_window.show_all ();
            		Gtk.main();
                 }catch (IOError.CANCELLED e) {
                     debug("stopped getting autherization code.");
                 }catch (Error e) {
                     debug("Error in authentication code : %s", e.message);
                 }
             }
             return true;

        }

        public async bool token_js_adapter_renew_token (
        						Cancellable? cancellable = null) {
            if (cancellable == null || (!cancellable.is_cancelled())){
            	try {
            		stdout.printf(" Application renewing token\n");
            		yield web_view.run_javascript("javascript:renewToken();");
                 }catch (IOError.CANCELLED e) {
                     debug("stopped renewing token.\n");
                 }catch (Error e) {
                     debug("Error in renewing token : %s\n", e.message);
                 }
             }
             stdout.printf(" Application renewing finished\n");
             return true;

        }

        public async bool token_js_adapter_get_token (string id,
        					string secret, string uri,
        					Cancellable? cancellable = null) {

		    try {
		    	SList<Soup.Cookie> list = new SList<Soup.Cookie> ();
		        var session = new Soup.Session();
		        var message = new Soup.Message("POST", "https://zuel.com/auth/realms/zuel/protocol/openid-connect/token");
		        message.request_headers.append("Content-Type", "application/x-www-form-urlencoded");

		        string req_body = "grant_type=authorization_code&code=" + authorization_code + "&client_id=" + id + "&redirect_uri=" + uri + "&state=" + state;
		        message.set_request("application/x-www-form-urlencoded", Soup.MemoryUse.TEMPORARY,req_body.data);
		        stdout.printf ("Sending request to get token =>%s \n", req_body);
		        var cookies = yield cookie_mgr.get_cookies ("https://zuel.com", null);
		        stdout.printf ("Cookies from cookie mgr: (%u)\n", cookies.length ());
		        foreach (Soup.Cookie c in cookies) {
					stdout.printf ("  %s: %s\n", c.name, c.value);
					list.append(c);
				}
				Soup.cookies_to_request (list, message);
		        session.send_async(message, null, (obj, result) => {
	            	stdout.printf ("Response =>%s \n",message.status_code.to_string());
	            	if (message.status_code == Soup.Status.OK) {
	   		        	message.response_headers.foreach ((name, val) => {
        					stdout.printf ("Response Header Data =>%s = %s\n", name, val);
        				});
	                	var response = message.response_body.flatten ().data;
	                	stdout.printf ("Access token data =>%s\n", (string)response);
	                	var json = Json.from_string ((string)response);
	                	string access_token = (string)json.get_string();
	                	stdout.printf ("Access token =>%s\n", access_token);
	            	} else {
	                	stdout.printf ("Retreiving token failed\n");
	            	}
	        	});

		    } catch (Error e) {
		        debug("Error in authentication code : %s", e.message);
		    }
            return (true);
        }

    }
}
