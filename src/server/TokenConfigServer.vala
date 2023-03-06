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

	public class KeyInfo {
		public string n;
		public string e;

		public KeyInfo() {
			n = "";
			e = "";
		}

		public bool read(string filename) {
			try {
				uint8[] contents;
				string etag;

    			if(filename.length == 0)
    				return false;

    			var file = File.new_for_path(filename);
    			file.load_contents(null, out contents, out etag);

    			Json.Parser parser = new Json.Parser ();
				parser.load_from_data ((string)contents);

				Json.Node root = parser.get_root ();
				var root_obj = root.get_object();
				var keys_node = root_obj.get_member("keys");
				if (keys_node.get_node_type () == Json.NodeType.ARRAY) {
					var key_array = keys_node.get_array();
					stdout.printf("Traverse Key Array\n");
					foreach(var key_node in key_array.get_elements()) {
						if (key_node.get_node_type () == Json.NodeType.OBJECT) {
							var key_obj = key_node.get_object();
							var alg = key_obj.get_string_member("alg");
							if (alg != "RS256")
								continue;

							n = key_obj.get_string_member("n");
							e = key_obj.get_string_member("e");
							stdout.printf("Key N: %s\n", n);
							stdout.printf("Key E: %s\n", e);
							return true;
						}
					}
				}

			} catch (Error e) {
				print ("Unable to parse the Certificate Json File: %s\n", e.message);
			}
			return false;
    	}
	}

    [DBus (name = "com.zuel.token")]
    public class TokenConfigServerInterfaceImpl : Object, TokenConfigServerInterface {

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
					if (ret_code = config_server.validate_jwt_signature(token, t_info)) {
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
        private KeyInfo key_info;
        // from RFC 4880
		private string hash_padding = "01" + string.nfill(404,'f') + "00";
		// from RFC 4880 section 5.2.2
		private string hash_header = "3031300d060960864801650304020105000420";


        public TokenConfigServer () throws Error {
            Object ();
            token_config_server_interface_impl = new TokenConfigServerInterfaceImpl (this);
            key_info = new KeyInfo();
            init ();
            GCrypt.control(GCrypt.ControlCommand.SET_DEBUG_FLAGS, 0xFFFFFFFF);
            GCrypt.control(GCrypt.ControlCommand.SET_VERBOSITY, 10);
            GCrypt.control(GCrypt.ControlCommand.DISABLE_SECMEM);
            GCrypt.control(GCrypt.ControlCommand.INITIALIZATION_FINISHED);
        }

        public bool init (Cancellable? cancellable = null) throws Error {
            Bus.own_name (BusType.SESSION, "com.zuel.token", BusNameOwnerFlags.NONE,
                          handle_bus_aquired,
                          () => {},
                          () => stderr.printf ("TokenConfigServer: Could not aquire Dbus name\n"));

			var ret_code = key_info.read("../../data/certs.json");
			if(!ret_code) {
				stdout.printf("Reading Keys File failed\n");
				// This is not needed. Just to make sure that it doesn't fail if certs.json is not available
				key_info.n = "o8Kfms6YGQZFd8p1wQRP_YWHZEXoQchQ9QIbNfHsWhUdiwH65arbxOprz7Zhn3maw-posZI3K8Ce86Pc5gjJqZkOcK-0YlfTifSdygXICgMXeNmZ4keaQrJVSrNEfhLg66iXTzH0XyniKFEmcIToa2YPVVWfb1RrnUOkPF4Z2RUYI0-fr-g8ZLKYIQRUvC04W3bkrXOT1dR-ati4p7w4qBvElZsuuATWH6FSyIib1uT5UmfeSFZWLBDJmBI-QaZRnBvpfkc9oeSI_f-UbBadYLZEpx5LdIUgzzxRgvjqCfAytMFMT1Lu8n6Khn-F3heGX9aDSdUAkruXPfrFc_ceJQ";
        		key_info.e = "AQAB";
        		base64_url_decode(ref key_info.n);
				base64_url_decode(ref key_info.e);
				return false;
			}
			else {
				base64_url_decode(ref key_info.n);
				base64_url_decode(ref key_info.e);
			}
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

            stdout.printf ("TokenConfigServer: decoding token\n");
            string[] token_parts = token.split(".");
            //convert to Base64 from Base64URL encoding
            string token_part = token_parts[1];
    		base64_url_decode(ref token_part);

			string payload_string = (string) Base64.decode(token_part);
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

		private string base64_url_decode (ref string input) {
			input = input.replace ("-", "+").replace("_", "/");
			switch (input.length % 4) {
				case 0: break;
				case 2: input += "=="; break;
				case 3: input += "="; break;
				default:
					stdout.printf("Illegal formation of Base 64 URL data\n");
					break;

    		}
    		return input;
		}

		private uint8[] hex_to_uint8 (string hex_data) {
            var out_bytes = new uint8[hex_data.length/2];
            for (int i =0; i < hex_data.length; i+=2) {
            	out_bytes[i/2] = (uint8)long.parse(hex_data.substring(i,2), 16);
            }
            return out_bytes;
        }

		public bool validate_jwt_signature(string token, TokenInfo token_info) {

			string pub_key_sexp_format, signature_sexp_format, input_sexp_format;
			GCrypt.SExp pub_key_sexp, signature_sexp, input_sexp;

            stdout.printf ("TokenConfigServer: Validating signature\n");

			// Validate the token time
            int64 time_sec = GLib.get_real_time () / 1000000;
            stdout.printf("Token Time: %"+ int64.FORMAT_MODIFIER +"d, Current Time:%" + int64.FORMAT_MODIFIER +"d\n",
            				 token_info.time, time_sec);

            if(token_info.time >= time_sec)
            {
	            string[] token_parts = token.split(".");
	            string signature_part = token_parts[2];

				var mpi_n = new GCrypt.MPI(2048);
				var mpi_e = new GCrypt.MPI(2048);
				var mpi_sign = new GCrypt.MPI(2048);
				var mpi_hash = new GCrypt.MPI(2048);
				size_t nscanned, err_offset;
				char[] print_buffer = new char[2048];

            	string header_payload;
				GLib.ByteArray n_bytes = new ByteArray.take(GLib.Base64.decode(key_info.n));
				GLib.ByteArray e_bytes = new ByteArray.take(GLib.Base64.decode(key_info.e));

				// Public Key n encoding
            	pub_key_sexp_format = "(public-key (rsa (n %M) (e %M)))";
            	var err = GCrypt.MPI.scan( out mpi_n, GCrypt.MPI.Format.USG, n_bytes.data,
            								 (size_t)n_bytes.len, out nscanned );
            	stdout.printf(" MPI Scan n Error Code: %s\n", err.to_string());

            	// Public Key e encoding
            	err = GCrypt.MPI.scan( out mpi_e, GCrypt.MPI.Format.USG, e_bytes.data,
            								(size_t)e_bytes.len, out nscanned );
				stdout.printf(" MPI Scan e Error Code: %s\n", err.to_string());

            	err = GCrypt.SExp.build (out pub_key_sexp, out err_offset, pub_key_sexp_format,
            						mpi_n, mpi_e);
            	stdout.printf(" Public Key Error Code: %s\n", err.to_string());
            	pub_key_sexp.sprint(GCrypt.SExp.Format.ADVANCED, print_buffer);
				stdout.printf(" Public Key SExp: %s\n", (string)print_buffer );


            	// Header + Payload
            	header_payload = token_parts[0] + "." + token_parts[1];
            	string hashValue = GLib.Checksum.compute_for_string (ChecksumType.SHA256, header_payload);
            	string hashData = hash_padding + hash_header + hashValue;
            	// convert the hexadecimal string to uint array
            	uint8[] hash_bytes = hex_to_uint8(hashData);

            	err = GCrypt.MPI.scan( out mpi_hash, GCrypt.MPI.Format.USG, hash_bytes,
            								(size_t)hash_bytes.length, out nscanned );
            	stdout.printf(" Hash Scan Error Code: %s\n", err.to_string());
				input_sexp_format = "(data (flags raw) (value %M))";
            	err = GCrypt.SExp.build (out input_sexp, out err_offset, input_sexp_format,
            								mpi_hash);
            	stdout.printf(" Input Error Code: %s\n", err.to_string());
            	input_sexp.sprint(GCrypt.SExp.Format.ADVANCED, print_buffer);
				stdout.printf(" Input SExp: %s\n", (string)print_buffer );

            	// signature formatting
				base64_url_decode(ref signature_part);
				GLib.ByteArray sign_bytes = new ByteArray.take(GLib.Base64.decode(signature_part));

            	signature_sexp_format = "(sig-val(rsa(s %M)))";
				err = GCrypt.MPI.scan( out mpi_sign, GCrypt.MPI.Format.USG, sign_bytes.data,
            								(size_t)sign_bytes.len, out nscanned );
				stdout.printf(" MPI Scan Sign Error Code: %s\n", err.to_string());

				err = GCrypt.SExp.build (out signature_sexp, out err_offset, signature_sexp_format,
            						mpi_sign);
            	stdout.printf(" Error Code: %s\n", err.to_string());
				signature_sexp.sprint(GCrypt.SExp.Format.ADVANCED, print_buffer);
				stdout.printf(" Signature SExp: %s\n", (string)print_buffer );

				// Verify the signature
            	err = GCrypt.PublicKey.verify(signature_sexp, input_sexp, pub_key_sexp);
            	stdout.printf(" Error Code: %s Source: %s\n", err.to_string(),
            					err.source_to_string());
            	if( err.code() == GCrypt.ErrorCode.NO_ERROR)
					return true;
				else
					return false;
			}
			else {
            	stdout.printf ("TokenConfigServer: Sending certificate check failure signal\n");
				token_config_server_interface_impl.token_verify_failed(0, token_info.name);
            	return false;
            }
		}

    }
}
