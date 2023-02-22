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
	public class TokenInfo {
		public string name;
    	public string email;
    	public int64 time;

    	public TokenInfo() {
    		name = "unknown";
    		email = "unknown";
    		time = 0;
    	}
	}

    [DBus (name = "com.zuel.token")]
    public class TokenConfigServerInterfaceImpl : Object, TokenConfigServerInterface {

        private string private_key;
        private class TokenConfigServer config_server;

        public TokenConfigServerInterfaceImpl(TokenConfigServer srvr) {
        	config_server = srvr;
        }

        public UserInfo get_user_info (int txn_id, string token) throws IOError {
        	var info = new TokenConfigServerInterface.UserInfo();
        	bool ret_code = false;

			try {
	            stdout.printf ("TokenConfigServer: received token:%s\n", token);
            	var t_info = config_server.decode_token(token);
            	if(t_info != null) {
					if (ret_code = config_server.verify_certificate(token, t_info)) {
            			info.name = t_info.name;
            			info.email = t_info.email;
					}
					else {
            			info.name = "unknown";
            			info.email = "unknown";
					}
            	}
			} catch (Error e) {
				print ("Unable to decode the token: %s\n", e.message);
			}

            return info;
        }

    }


    [SingleInstance]
    public class TokenConfigServer : Object, Initable {
        private TokenConfigServerInterfaceImpl token_config_server_interface_impl;

        public TokenConfigServer () throws Error {
            Object ();
            token_config_server_interface_impl = new TokenConfigServerInterfaceImpl (this);
            init ();
        }

        public bool init (Cancellable? cancellable = null) throws Error {
            Bus.own_name (BusType.SESSION, "com.zuel.token", BusNameOwnerFlags.NONE,
                          handle_bus_aquired,
                          () => {},
                          () => stderr.printf ("TokenConfigServer: Could not aquire Dbus name\n"));
            return true;
        }

        void handle_bus_aquired (DBusConnection conn) {
            try {
                conn.register_object ("/com/zuel/token", token_config_server_interface_impl);
            } catch (IOError e) {
                stderr.printf ("TokenConfigServer:Could not register Dbus service\n");
            }
        }

        public TokenInfo? decode_token (string token) throws Error{
        	var t_info = new TokenInfo();

            stdout.printf ("TokenConfigServer: decoding token:%s\n", token);
            string[] token_parts = token.split(".");
            //convert to Base64 from Base64URL encoding
            string token_part = token_parts[1].replace ("-", "+").replace("_", "/");
    		while (token_part.length % 4 != 0) {
        		token_part += "=";
    		}

			string payload_string = (string) Base64.decode(token_part);
			stdout.printf ("Signature: %s\n", token_parts[2]);
			Json.Parser parser = new Json.Parser ();
			try {
				parser.load_from_data (payload_string);
				Json.Node node = parser.get_root ();
				unowned Json.Object obj = node.get_object ();
				foreach (unowned string name in obj.get_members ()) {
					unowned Json.Node item = obj.get_member (name);
					if (item.get_node_type () == Json.NodeType.VALUE) {
						stdout.printf("%s : %s\n", name, obj.get_string_member(name));
						switch (name) {
							case "name" :
								t_info.name = obj.get_string_member(name);
								break;
							case "email" :
								t_info.email = obj.get_string_member(name);
								break;
							case "exp" :
								t_info.time = obj.get_int_member(name);
								stdout.printf("%s : " + "%"+ int64.FORMAT_MODIFIER +"d\n",
										name, t_info.time);
								break;

							default:
								break;
						}
					}
				}
			} catch (Error e) {
				print ("Unable to parse the string: %s\n", e.message);
			}

            return t_info;
        }

        public bool verify_certificate (string token, TokenInfo token_info) {

            stdout.printf ("TokenConfigServer: Verifyiing certificate\n");
            string[] token_parts = token.split(".");
            string token_part = token_parts[2];
            int64 time_sec = GLib.get_real_time () / 1000000;
            stdout.printf("%"+ int64.FORMAT_MODIFIER +"d\n", token_info.time);
            stdout.printf("%"+ int64.FORMAT_MODIFIER +"d\n", time_sec);

            if(token_info.time >= time_sec)
            	return true;
            else {
            	stdout.printf ("TokenConfigServer: Sending certificate check failure signal\n");
				token_config_server_interface_impl.token_verify_failed(0, token_info.name);
            	return false;
            }
        }

    }
}
