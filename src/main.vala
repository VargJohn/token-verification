/* main.vala
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

int main (string[] args) {
    try {
        string[] server_process_cmd = {"./tokenverification-server"};
        string[] gui_process_cmd = {"./tokenverification-gui"};

        var token_config_server_process = new Subprocess.newv(server_process_cmd, STDIN_PIPE);
        token_config_server_process.wait_async();

        var token_application_process = new Subprocess.newv(gui_process_cmd, STDIN_PIPE);
        token_application_process.wait_async();

    } catch (Error error) {
        print (@"Error: $(error.message)\n");
    }
    new MainLoop ().run ();
    return 0;
}

