--[[
  Routines for Keyence LJ-V7000 laser scanner ethernet protocol dissection
  Copyright (c) 2015, G.A. vd. Hoorn
  All rights reserved.

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

  ---

  Wireshark dissector in Lua for the Keyence LJ-V (7000) Ultra-High Speed
  In-Line Profilometer ethernet protocol.

  Tested on Wireshark 1.11.x and 1.12.x on Windows and Linux.

  Note: packet / command names are only loosely based on the available
        documentation and have been adapted sometimes to better fit available
        UI space.

  For known issues and open feature requests, see [1].

  Author: G.A. vd. Hoorn

  [1] https://github.com/gavanderhoorn/packet-keyence-lj-v7000/issues
]]
do

	--
	-- constants
	--
	local DISSECTOR_VERSION             = "0.0.0"

	local DEFAULT_KEYENCE_PORT          = 24691
	local DEFAULT_KEYENCE_HS_PORT       = 24692

	local PFX_LEN                       =  4
	local HDR_LEN                       = 12



	--
	-- 
	--
	local REQ_RESP_REQUEST                       = 0x00F0
	local REQ_RESP_REPLY                         = 0xF000


	--
	-- return codes
	--
	local RET_CODE_NORMAL                        = 0x00
	local RET_CODE_TIMEOUT                       = 0x11
	local RET_CODE_FIXED_VALUE_SETTING_ERROR0    = 0x21
	local RET_CODE_FIXED_VALUE_SETTING_ERROR1    = 0x22


	--
	-- response body return codes
	--
	local RET_CODE_BODY_NORMAL                   = 0x00
	local RET_CODE_BODY_UNDEFINED_CMD            = 0x31
	local RET_CODE_BODY_CMD_LENGTH_ERR           = 0x32
	local RET_CODE_BODY_STATUS_ERROR             = 0x41
	local RET_CODE_BODY_PARAMETER_ERROR          = 0x42


	--
	-- Controller status codes
	--
	local CTRLR_STATUS_MEASURING                 = 0x00
	local CTRLR_STATUS_SYSTEM_ERROR              = 0xFF


	--
	-- Commands
	--
	local CMD_UNKNOWN_0x01                       = 0x01

	local CMD_GET_SYS_ERROR_INFO                 = 0x04
	local CMD_CLEAR_SYS_ERROR                    = 0x05

	local CMD_TRIGGER                            = 0x21
	local CMD_START_BATCH_MEASUREMENTS           = 0x22
	local CMD_STOP_BATCH_MEASUREMENTS            = 0x23
	local CMD_AUTO_ZERO                          = 0x24
	local CMD_TIMING                             = 0x25
	local CMD_RESET                              = 0x26
	local CMD_CLEAR_MEMORY                       = 0x27

	local CMD_GET_SETTING                        = 0x31
	local CMD_SET_SETTING                        = 0x32
	local CMD_REFLECT_SETTING                    = 0x33
	local CMD_CHECK_SAVE_STATUS                  = 0x34
	local CMD_UPDATE_WRITE_SETTINGS              = 0x35

	local CMD_GET_TIME                           = 0x37

	local CMD_CHANGE_PROGRAM                     = 0x39

	local CMD_INITIALIZE_SETTINGS                = 0x3D

	local CMD_GET_NEWEST_MEASUREMENT_VALUE       = 0x41
	local CMD_GET_PROFILE_HIGHSPEED_MODE         = 0x42
	local CMD_GET_BATCH_PROFILES_HIGHSPEED_MODE  = 0x43
	local CMD_GET_PROFILE_ADVANCED_MODE          = 0x44
	local CMD_GET_BATCH_PROFILE_ADVANCED_MODE    = 0x45

	local CMD_PREPARE_HIGH_SPEED_PROFILE_COMM    = 0x47
	local CMD_STOP_HIGH_SPEED_PROFILE_COMM       = 0x48
	local CMD_GET_PROFILES_WITH_RANGE_SPEC       = 0x49
	local CMD_GET_BATCH_PROFILES_WITH_RANGE_SPEC = 0x4A

	local CMD_START_STORAGE                      = 0x51
	local CMD_STOP_STORAGE                       = 0x52

	local CMD_GET_STORAGE_STATUS                 = 0x54

	local CMD_GET_ACTIVE_PROGRAM                 = 0x63

	local CMD_START_HIGH_SPEED_PROFILE_COMM      = 0xA0





	--
	-- Command 0x31 - GetSetting constants
	--
	local CMD_31_LVL_WRITE_SETTINGS_AREA         = 0x00
	local CMD_31_LVL_RUNNING_SETTINGS_AREA       = 0x01
	local CMD_31_LVL_SAVE_AREA                   = 0x02

	local CMD_31_TYPE_ENVIRONMENT_SETTINGS       = 0x01
	local CMD_31_TYPE_COMMON_SETTINGS            = 0x02
	local CMD_31_TYPE_PROGRAM_00                 = 0x10
	local CMD_31_TYPE_PROGRAM_01                 = 0x11
	local CMD_31_TYPE_PROGRAM_02                 = 0x12
	local CMD_31_TYPE_PROGRAM_03                 = 0x13
	local CMD_31_TYPE_PROGRAM_04                 = 0x14
	local CMD_31_TYPE_PROGRAM_05                 = 0x15
	local CMD_31_TYPE_PROGRAM_06                 = 0x16
	local CMD_31_TYPE_PROGRAM_07                 = 0x17
	local CMD_31_TYPE_PROGRAM_08                 = 0x18
	local CMD_31_TYPE_PROGRAM_09                 = 0x19
	local CMD_31_TYPE_PROGRAM_0A                 = 0x1A
	local CMD_31_TYPE_PROGRAM_0B                 = 0x1B
	local CMD_31_TYPE_PROGRAM_0C                 = 0x1C
	local CMD_31_TYPE_PROGRAM_0D                 = 0x1D
	local CMD_31_TYPE_PROGRAM_0E                 = 0x1E
	local CMD_31_TYPE_PROGRAM_0F                 = 0x1F

	local CMD_31_CAT_TRIGGER_SETTINGS            = 0x00
	local CMD_31_CAT_IMAGE_SETTINGS              = 0x01
	local CMD_31_CAT_PROFILE                     = 0x02
	local CMD_31_CAT_MASTER_REGIST               = 0x03
	local CMD_31_CAT_POS_CORRECTION              = 0x04
	local CMD_31_CAT_PROFILE_MASK                = 0x05
	local CMD_31_CAT_OUT                         = 0x06
	local CMD_31_CAT_TERMINAL                    = 0x07
	local CMD_31_CAT_STORAGE                     = 0x08
	local CMD_31_CAT_PROGRAM_NAME                = 0x09
	local CMD_31_CAT_BATCH                       = 0xFF

	local CMD_31_ITEM_ENV_DEV_NAME               = 0x00
	local CMD_31_ITEM_ENV_OP_NEXT_PON            = 0x01
	local CMD_31_ITEM_ENV_HS_BAND_RESTRICT       = 0x02
	local CMD_31_ITEM_ENV_HS_MTU                 = 0x03
	local CMD_31_ITEM_ENV_NET_IP                 = 0x04
	local CMD_31_ITEM_ENV_NET_SUBNET             = 0x05
	local CMD_31_ITEM_ENV_NET_GW                 = 0x06
	local CMD_31_ITEM_ENV_TCP_CMD_PORT           = 0x07
	local CMD_31_ITEM_ENV_TCP_HS_PORT            = 0x08

	local CMD_31_ITEM_ENV_BAUD_RATE              = 0x0A
	local CMD_31_ITEM_ENV_PARITY                 = 0x0B

	local CMD_31_ITEM_COMMON_OPER_MODE           = 0x00
	local CMD_31_ITEM_COMMON_MEM_ALLOC           = 0x01
	local CMD_31_ITEM_COMMON_OPER_MEM_FULL       = 0x02
	local CMD_31_ITEM_COMMON_PARALLEL_IMG        = 0x03
	local CMD_31_ITEM_COMMON_STROBE_OUTP_T       = 0x04

	local CMD_31_ITEM_COMMON_TRG_MIN_INP_T       = 0x06
	local CMD_31_ITEM_COMMON_ENC_MIN_INP_T       = 0x07
	local CMD_31_ITEM_COMMON_CTRL_MIN_INP_T      = 0x08
	local CMD_31_ITEM_COMMON_CHANGE_PROG         = 0x09

	local CMD_34_RESULT_ACCESS                   = 0x00
	local CMD_34_RESULT_NO_ACCESS                = 0x01


	--
	-- Command 0x47 - Start position of sending
	--
	local CMD_47_START_POS_FROM_PREVIOUS         = 0x00
	local CMD_47_START_POS_FROM_OLDEST_DATA      = 0x01
	local CMD_47_START_POS_FROM_NEXT_DATA        = 0x02








	--
	-- misc
	--

	-- cache globals to local for speed
	local _F = string.format

	-- wireshark API globals
	local Pref = Pref

	-- minimal config
	local config = {
		include_fixed_fields = false
	}

	-- a context
	local ctx = {}






	--
	-- constant -> string rep tables
	--

	local set_not_set_str = {
		[0] = "Not set",
		[1] = "Set"
	}

	local in_valid_str = {
		[0] = "Invalid",
		[1] = "Valid"
	}

	local req_resp_str = {
		[REQ_RESP_REQUEST] = "Request",
		[REQ_RESP_REPLY]   = "Reply"
	}

	local ret_codes_str = {
		[RET_CODE_NORMAL                       ] = "Normal (no error)",
		[RET_CODE_TIMEOUT                      ] = "Timeout error",
		[RET_CODE_FIXED_VALUE_SETTING_ERROR0   ] = "Fixed value setting error 0",
		[RET_CODE_FIXED_VALUE_SETTING_ERROR1   ] = "Fixed value setting error 1"
	}

	local body_ret_codes_str = {
		[RET_CODE_BODY_NORMAL                  ] = "Normal",
		[RET_CODE_BODY_UNDEFINED_CMD           ] = "Undefined command error",
		[RET_CODE_BODY_CMD_LENGTH_ERR          ] = "Command length error",
		[RET_CODE_BODY_STATUS_ERROR            ] = "Status error",
		[RET_CODE_BODY_PARAMETER_ERROR         ] = "Parameter error"
	}

	local ctrlr_status_str = {
		[CTRLR_STATUS_MEASURING                ] = "Measuring",
		[CTRLR_STATUS_SYSTEM_ERROR             ] = "System error"
	}

	local cmd_code_str = {
		[CMD_UNKNOWN_0x01                      ] = "Unknown01",
		[CMD_GET_SYS_ERROR_INFO                ] = "GetError",
		[CMD_CLEAR_SYS_ERROR                   ] = "ClearError",
		[CMD_TRIGGER                           ] = "Trigger",
		[CMD_START_BATCH_MEASUREMENTS          ] = "StartMeasure",
		[CMD_STOP_BATCH_MEASUREMENTS           ] = "StopMeasure",
		[CMD_AUTO_ZERO                         ] = "AutoZero",
		[CMD_TIMING                            ] = "Timing",
		[CMD_RESET                             ] = "Reset",
		[CMD_CLEAR_MEMORY                      ] = "ClearMemory",
		[CMD_GET_SETTING                       ] = "GetSetting",
		[CMD_SET_SETTING                       ] = "SetSetting",
		[CMD_REFLECT_SETTING                   ] = "ReflectSetting",
		[CMD_CHECK_SAVE_STATUS                 ] = "CheckMemoryAccess",
		[CMD_UPDATE_WRITE_SETTINGS             ] = "RewriteTemporarySetting",
		[CMD_GET_TIME                          ] = "GetTime",
		[CMD_CHANGE_PROGRAM                    ] = "ChangeActiveProgram",
		[CMD_INITIALIZE_SETTINGS               ] = "InitializeSetting",

		[CMD_GET_NEWEST_MEASUREMENT_VALUE      ] = "GetMeasurementValue",
		[CMD_GET_PROFILES_WITH_RANGE_SPEC      ] = "GetProfile",
		[CMD_GET_BATCH_PROFILES_WITH_RANGE_SPEC] = "GetBatchProfile",

		[CMD_START_STORAGE                     ] = "StartStorage",
		[CMD_STOP_STORAGE                      ] = "StopStorage",
		[CMD_GET_STORAGE_STATUS                ] = "GetStorageStatus",

		[CMD_GET_ACTIVE_PROGRAM                ] = "GetActiveProgram",

		[CMD_GET_PROFILE_HIGHSPEED_MODE        ] = "GetProfile (HS mode)",
		[CMD_GET_BATCH_PROFILES_HIGHSPEED_MODE ] = "GetBatchProfile (HS mode)",
		[CMD_GET_PROFILE_ADVANCED_MODE         ] = "GetProfile (Advanced)",
		[CMD_GET_BATCH_PROFILE_ADVANCED_MODE   ] = "GetBatchProfile (Advanced)",
		[CMD_PREPARE_HIGH_SPEED_PROFILE_COMM   ] = "PrepareHighSpeedCommunication",
		[CMD_STOP_HIGH_SPEED_PROFILE_COMM      ] = "StopHighSpeedCommunication",
		[CMD_START_HIGH_SPEED_PROFILE_COMM     ] = "StartHighSpeedCommunication"
	}

	local cmd_31_level_str = {
		[CMD_31_LVL_WRITE_SETTINGS_AREA        ] = "Write settings area",
		[CMD_31_LVL_RUNNING_SETTINGS_AREA      ] = "Running settings area",
		[CMD_31_LVL_SAVE_AREA                  ] = "Save area"
	}

	local cmd_31_type_str = {
		[CMD_31_TYPE_ENVIRONMENT_SETTINGS      ] = "Environment Settings",
		[CMD_31_TYPE_COMMON_SETTINGS           ] = "Common Settings",
		[CMD_31_TYPE_PROGRAM_00                ] = "Program 0",
		[CMD_31_TYPE_PROGRAM_01                ] = "Program 1",
		[CMD_31_TYPE_PROGRAM_02                ] = "Program 2",
		[CMD_31_TYPE_PROGRAM_03                ] = "Program 3",
		[CMD_31_TYPE_PROGRAM_04                ] = "Program 4",
		[CMD_31_TYPE_PROGRAM_05                ] = "Program 5",
		[CMD_31_TYPE_PROGRAM_06                ] = "Program 6",
		[CMD_31_TYPE_PROGRAM_07                ] = "Program 7",
		[CMD_31_TYPE_PROGRAM_08                ] = "Program 8",
		[CMD_31_TYPE_PROGRAM_09                ] = "Program 9",
		[CMD_31_TYPE_PROGRAM_0A                ] = "Program A",
		[CMD_31_TYPE_PROGRAM_0B                ] = "Program B",
		[CMD_31_TYPE_PROGRAM_0C                ] = "Program C",
		[CMD_31_TYPE_PROGRAM_0D                ] = "Program D",
		[CMD_31_TYPE_PROGRAM_0E                ] = "Program E",
		[CMD_31_TYPE_PROGRAM_0F                ] = "Program F"
	}

	local cmd_31_category_str = {
		[CMD_31_CAT_TRIGGER_SETTINGS           ] = "Unused / Trigger",
		[CMD_31_CAT_IMAGE_SETTINGS             ] = "Image",
		[CMD_31_CAT_PROFILE                    ] = "Profile",
		[CMD_31_CAT_MASTER_REGIST              ] = "Master Regist",
		[CMD_31_CAT_POS_CORRECTION             ] = "Position Correction",
		[CMD_31_CAT_PROFILE_MASK               ] = "Profile Mask",
		[CMD_31_CAT_OUT                        ] = "OUT",
		[CMD_31_CAT_TERMINAL                   ] = "Terminal",
		[CMD_31_CAT_STORAGE                    ] = "Storage",
		[CMD_31_CAT_PROGRAM_NAME               ] = "Program Name",
		-- not really a category, but this is convenient for mapping to str in field
		[CMD_31_CAT_BATCH                      ] = "Batch (all settings)"
	}

	-- NOTE: this table can only be used if 'type' == 0x00 (Environment Setting)
	local cmd_31_item_env_str = {
		[CMD_31_ITEM_ENV_DEV_NAME              ] = "Device name",
		[CMD_31_ITEM_ENV_OP_NEXT_PON           ] = "Operation at next power on",
		[CMD_31_ITEM_ENV_HS_BAND_RESTRICT      ] = "High-speed communication band restriction",
		[CMD_31_ITEM_ENV_HS_MTU                ] = "MTU during high-speed communication",
		[CMD_31_ITEM_ENV_NET_IP                ] = "IP address",
		[CMD_31_ITEM_ENV_NET_SUBNET            ] = "Subnet mask",
		[CMD_31_ITEM_ENV_NET_GW                ] = "Gateway",
		[CMD_31_ITEM_ENV_TCP_CMD_PORT          ] = "TCP command port number",
		[CMD_31_ITEM_ENV_TCP_HS_PORT           ] = "TCP high-speed port number",
		[CMD_31_ITEM_ENV_BAUD_RATE             ] = "Baud rate",
		[CMD_31_ITEM_ENV_PARITY                ] = "Parity"
	}

	local cmd_31_item_common_str = {
		[CMD_31_ITEM_COMMON_OPER_MODE          ] = "Operation mode",
		[CMD_31_ITEM_COMMON_MEM_ALLOC          ] = "Memory allocation",
		[CMD_31_ITEM_COMMON_OPER_MEM_FULL      ] = "Operation when memory full",
		[CMD_31_ITEM_COMMON_PARALLEL_IMG       ] = "Parallel imaging",
		[CMD_31_ITEM_COMMON_STROBE_OUTP_T      ] = "Strobe output time",
		[CMD_31_ITEM_COMMON_TRG_MIN_INP_T      ] = "TRG minimum input time",
		[CMD_31_ITEM_COMMON_ENC_MIN_INP_T      ] = "ENCODER minimum input time",
		[CMD_31_ITEM_COMMON_CTRL_MIN_INP_T     ] = "Control terminal minimum input time",
		[CMD_31_ITEM_COMMON_CHANGE_PROG        ] = "Change program"
	}

	local cmd_34_result_str = {
		[CMD_34_RESULT_ACCESS                  ] = "Access",
		[CMD_34_RESULT_NO_ACCESS               ] = "No Access"
	}

	local cmd_47_start_pos_str = {
		[CMD_47_START_POS_FROM_PREVIOUS        ] = "From previous send complete position",
		[CMD_47_START_POS_FROM_OLDEST_DATA     ] = "From oldest data",
		[CMD_47_START_POS_FROM_NEXT_DATA       ] = "From next data"
	}








	--
	-- Protocol object creation and setup
	--
	local p_keyence_ljv7k_tcp = Proto("KLJV7E", "Keyence LJ-V7000 Ethernet")

	-- preferences
	p_keyence_ljv7k_tcp.prefs["version_txt"         ] = Pref.statictext(_F("Dissector version: v%s", DISSECTOR_VERSION), "Shows dissector information.")
	p_keyence_ljv7k_tcp.prefs["include_fixed_fields"] = Pref.bool("Include fixed fields", false, "Add 'fixed-fields' to dissection tree?")


	--
	-- protocol fields
	--
	local f = p_keyence_ljv7k_tcp.fields

	-- protocol fields: prefix and header
	f.pfx_hdr_len    = ProtoField.uint32("kljv7e.pfx.length"     , "Packet Length"      , base.DEC, nil           , nil, "Total size of packet in bytes, excluding this field")
	f.hdr_version    = ProtoField.uint16("kljv7e.hdr.version"    , "Packet Version?"    , base.HEX, nil           , nil, "TODO")
	f.hdr_reqresp    = ProtoField.uint16("kljv7e.hdr.reqresp"    , "ReqResp?"           , base.HEX, req_resp_str  , nil, "TODO")
	f.hdr_ret_code   = ProtoField.uint8 ("kljv7e.hdr.return_code", "Return Code"        , base.HEX, ret_codes_str , nil, "Command processing return code")
	f.hdr_body_len   = ProtoField.uint32("kljv7e.hdr.body_length", "Body Length"        , base.DEC, nil           , nil, "Total size of the 'Body' part of the message, in bytes")

	-- body
	f.body_cmd_code      = ProtoField.uint8 ("kljv7e.body.cmd_code"    , "Command Code"          , base.HEX, cmd_code_str      , nil, "Message Command Code")
	f.body_ret_code      = ProtoField.uint8 ("kljv7e.body.return_code" , "Return Code"           , base.HEX, body_ret_codes_str, nil, "Returning if the command has processed normally")
	f.body_ctrlr_status  = ProtoField.uint8 ("kljv7e.body.ctrlr_status", "Controller Status"     , base.HEX, ctrlr_status_str  , nil, "Status of each controller")
	f.body_act_prog_nr   = ProtoField.uint8 ("kljv7e.body.act_prog_nr" , "Active Program Number" , base.DEC, nil               , nil, "Active program No. is stored")

	-- other fields for the different command codes


	-- 0x24 - Auto zero
	-- command
	f.cmd_24_oper_desig      = ProtoField.uint8 ("kljv7e.cmd24.oper_desig"      , "Operation Designation"              , base.HEX, {[0] = "Auto zero on"}, nil, "TODO")
	f.cmd_24_oper_tgt_d_meth = ProtoField.uint8 ("kljv7e.cmd24.oper_tgt_d_meth" , "Operation Target Designation Method", base.HEX, {[0] = "OUT target as bit", [1] = "OUT target as ZERO assignment"}, nil, "TODO")
	f.cmd_24_fixed0          = ProtoField.uint16("kljv7e.cmd24.fixed0"          , "Fixed0"                             , base.HEX, nil, nil, "TODO")
	f.cmd_24_oper_target     = ProtoField.uint32("kljv7e.cmd24.oper_target"     , "Operation Target"                   , base.HEX, nil, nil, "TODO")
	-- TODO: add bit table for OUT bits in oper_target (depends on oper_tgt_d_meth value)
	-- response


	-- 0x31 - Get Setting
	-- command
	f.cmd_31_fixed0        = ProtoField.uint32("kljv7e.cmd31.fixed0"       , "Fixed0"          , base.HEX, nil, nil, "TODO")
	f.cmd_31_level_to_read = ProtoField.uint8 ("kljv7e.cmd31.level_to_read", "Level to Read"   , base.HEX, cmd_31_level_str, nil, "TODO")
	f.cmd_31_setting_type  = ProtoField.uint8 ("kljv7e.cmd31.setting_type" , "Setting Type"    , base.HEX, cmd_31_type_str, nil, "TODO")

	-- define this multiple times so we can configure a different string mapping table
	f.cmd_31_setting_cat     = ProtoField.uint8 ("kljv7e.cmd31.setting_cat"  , "Setting Category", base.HEX, nil, nil, "TODO")
	f.cmd_31_setting_cat_str = ProtoField.uint8 ("kljv7e.cmd31.setting_cat"  , "Setting Category", base.HEX, cmd_31_category_str, nil, "TODO")

	-- define this multiple times so we can configure a different string mapping table
	f.cmd_31_setting_item        = ProtoField.uint8 ("kljv7e.cmd31.setting_item" , "Setting Item"    , base.HEX, nil, nil, "TODO")
	f.cmd_31_setting_item_env    = ProtoField.uint8 ("kljv7e.cmd31.setting_item" , "Setting Item"    , base.HEX, cmd_31_item_env_str, nil, "TODO")
	f.cmd_31_setting_item_common = ProtoField.uint8 ("kljv7e.cmd31.setting_item" , "Setting Item"    , base.HEX, cmd_31_item_common_str, nil, "TODO")

	f.cmd_31_rsvd0       = ProtoField.uint8 ("kljv7e.cmd31.rsvd0"        , "Reserved0"       , base.HEX, nil, nil, "TODO")
	f.cmd_31_setting_tgt = ProtoField.uint32("kljv7e.cmd31.setting_tgt"  , "Setting Target"  , base.HEX, nil, nil, "TODO")
	f.cmd_31_setting_val = ProtoField.bytes ("kljv7e.cmd31.setting_val"  , "Setting Value"   , "Value of the requested setting")
	-- response


	-- 0x32 - Set Setting
	-- command
	f.cmd_32_level_to_write = ProtoField.uint8 ("kljv7e.cmd32.level_to_write", "Destination level"  , base.HEX, cmd_31_level_str, nil, "TODO")
	f.cmd_32_setting_type   = ProtoField.uint8 ("kljv7e.cmd32.setting_type"  , "Setting Type"       , base.HEX, cmd_31_type_str, nil, "TODO")
	f.cmd_32_setting_cat    = ProtoField.uint8 ("kljv7e.cmd32.setting_cat"   , "Setting Category"   , base.HEX, nil, nil, "TODO")
	f.cmd_32_setting_item   = ProtoField.uint8 ("kljv7e.cmd32.setting_item"  , "Setting Item"       , base.HEX, nil, nil, "TODO")
	f.cmd_32_rsvd0          = ProtoField.uint8 ("kljv7e.cmd32.rsvd0"         , "Reserved0"          , base.HEX, nil, nil, "TODO")
	f.cmd_32_setting_tgt    = ProtoField.uint32("kljv7e.cmd32.setting_tgt"   , "Setting Target"     , base.HEX, nil, nil, "TODO")
	f.cmd_32_setting_val    = ProtoField.bytes ("kljv7e.cmd32.setting_val"   , "Setting Value"      , "Value of the requested setting")
	-- response
	f.cmd_32_detailed_err   = ProtoField.uint32("kljv7e.cmd32.detailed_err"  , "Detailed Error Code", base.HEX, nil, nil, "Detailed error info (see Section 9.2.9.4 in the LJ-V7000 Series Communication Library Reference Manual)")


	-- 0x33 - Reflect Setting
	-- command
	f.cmd_33_reflection_dest = ProtoField.uint8 ("kljv7e.cmd33.reflection_dest", "Reflection Destination", base.HEX, cmd_31_level_str, nil, "The setting value of the write settings area is reflected to.")
	-- response
	f.cmd_33_detailed_err    = ProtoField.uint32("kljv7e.cmd33.detailed_err"   , "Detailed Error Code"   , base.HEX, nil, nil, "Detailed error info (see Section 9.2.9.4 in the LJ-V7000 Series Communication Library Reference Manual)")


	-- 0x34 - Check Memory Access
	-- command
	-- response
	f.cmd_34_result = ProtoField.uint8("kljv7e.cmd34.result", "Result", base.HEX, cmd_34_result_str, nil, "TODO")


	-- 0x39 - Change Active Program
	-- command
	f.cmd_39_prog_nr = ProtoField.uint8("kljv7e.cmd39.prog_nr", "Program Number", base.HEX, nil, nil, "Program number to change to")
	-- response


	-- 0x42 - Get Profile(high-speed mode)
	-- command
	f.cmd_42_fixed0                  = ProtoField.uint32("kljv7e.cmd42.fixed0"                 , "Fixed0"                        , base.HEX, nil, nil, "")
	f.cmd_42_profile_bank            = ProtoField.uint8 ("kljv7e.cmd42.profile_bank"           , "Profile Bank"                  , base.HEX, {[0] = "Active surface", [1] = "Non active surface"}, nil, "Set profile get bank")
	f.cmd_42_get_profile             = ProtoField.uint8 ("kljv7e.cmd42.get_profile"            , "Get Profile"                   , base.HEX, {[0] = "From current", [1] = "From oldest", [2] = "Specify position"}, nil, "The way of specify to get profile")
	f.cmd_42_fixed1                  = ProtoField.uint16("kljv7e.cmd42.fixed1"                 , "Fixed1"                        , base.HEX, nil, nil, "")
	f.cmd_42_nr_of_profile           = ProtoField.uint32("kljv7e.cmd42.nr_of_profile"          , "Number of Profile"             , base.DEC, nil, nil, "The number of profile")
	f.cmd_42_nr_demanded_profile     = ProtoField.uint8 ("kljv7e.cmd42.nr_of_demanded_profile" , "Number of demanded profile"    , base.HEX, {[0] = "From current", [1] = "From oldest", [2] = "Specify position"}, nil, "The number of demanded profile")
	f.cmd_42_erase_data              = ProtoField.uint8 ("kljv7e.cmd42.erase_data"             , "Erase Data"                    , base.HEX, {[0] = "No", [1] = "Yes"}, nil, "Specifies whether or not to erase the profile data that was read and the profile data older than that")
	f.cmd_42_fixed2                  = ProtoField.uint16("kljv7e.cmd42.fixed2"                 , "Fixed2"                        , base.HEX, nil, nil, "")
	-- response
	f.cmd_42_prof_nr_cpit            = ProtoField.uint32("kljv7e.cmd42.prof_nr_cpit"           , "CurrentProfNo"                 , base.DEC, nil, nil, "The profile number at the current point in time")
	f.cmd_42_prof_nr_oldest_not_read = ProtoField.uint32("kljv7e.cmd42.prof_nr_oldest_not_read", "OldestProfNo"                  , base.DEC, nil, nil, "The profile number for the oldest profile out of those that were not read this time")
	f.cmd_42_prof_nr_oldest_read     = ProtoField.uint32("kljv7e.cmd42.prof_nr_oldest_read"    , "GetTopProfNo"                  , base.DEC, nil, nil, "The profile number for the oldest profile out of those that were read this time.")
	f.cmd_42_prof_read               = ProtoField.uint8 ("kljv7e.cmd42.prof_read"              , "GetProfCnt"                    , base.DEC, nil, nil, "The number of profiles that were read this time")
	f.cmd_42_profile_info            = ProtoField.bytes ("kljv7e.cmd42.profile_info"           , "Profile Info"                  , "Profile data")


	-- 0x47 - Profile data high-speed communication preparation
	-- command
	f.cmd_47_start_pos  = ProtoField.uint8 ("kljv7e.cmd47.start_pos", "Start position of sending", base.HEX, cmd_47_start_pos_str, nil, "Start position of sending")
	-- response
	f.cmd_47_start_code = ProtoField.uint32("kljv7e.cmd47.start_code", "Start Code", base.HEX, nil, nil, "TODO")
	f.cmd_47_ignore0    = ProtoField.bytes ("kljv7e.cmd47.ignore0"   , "Don't care", "Don't refer")


	-- 0xA0 - 
	-- command
	f.cmd_A0_47_fix      = ProtoField.uint8 ("kljv7e.cmdA0.fix47"     , "Fixed value field", base.HEX, nil, nil, "0x47 fix")
	f.cmd_A0_start_code  = ProtoField.uint32("kljv7e.cmdA0.start_code", "Start Code", base.HEX, nil, nil, "Specify start code in the response for Profile data high-speed communication preparation (0x47)")
	-- response








	--
	-- Helper functions
	--

	local function parse_uint(buf, offset, len)
		return buf(offset, len):le_uint()
	end

	local function parse_int(buf, offset, len)
		return buf(offset, len):le_int()
	end

	local function parse_uint64(buf, offset, len)
		return buf(offset, len):le_uint64()
	end

	local function parse_int64(buf, offset, len)
		return buf(offset, len):le_int64()
	end

	local function parse_float(buf, offset, len)
		return buf(offset, len):le_float()
	end

	local function tree_add(tree, field, buf, offset, len)
		return tree:add_le(field, buf(offset, len))
	end

	local function add_floatf_fmt(buf, tree, offset, len, text, format)
		if ((len % 4) ~= 0) or (len > 8) then return nil end

		return tree:add(buf(offset, len), text)
			:append_text(_F(": %s",
				_F(format,
				   parse_float(buf, offset, len)),
				   parse_uint(buf, offset, len)))
	end

	local function add_floatf(buf, tree, offset, len, text)
		return add_floatf_fmt(buf, tree, offset, len, text, "%14.9f")
	end

	local function str_or_none(arr, arg)
		return arr[arg] or "Unknown"
	end

	local function parse_cmd_code(buf, offset)
		-- return 'Command Code' field
		-- assume 'offset' points to start of packet
		return parse_uint(buf, offset + 16, 1)
	end

	local function parse_pkt_len(buf, offset)
		-- return 'Length' field
		-- assume 'offset' points to start of packet
		return parse_uint(buf, offset, 4)
	end

	local function is_request(buf)
		-- requests have byte 2 of header set to 0xF0
		-- header starts at byte 4
		local offset = 4 + 2
		local len = 1
		return (parse_uint(buf, offset, len) == 0xF0)
	end

	local function is_response(buf)
		return (not is_request(buf))
	end

	local function stringify_flagbits(bit_val, bit_tab)
		local temp = {}
		for k, v in pairs(bit_tab) do
			if (bit.band(bit_val, k) > 0) then table.insert(temp, v) end
		end
		return table.concat(temp, ", ")
	end

local function add_named_tree_field(buf, tree, offset, len, text)
	local data = buf(offset, len)
	local st = tree:add(data, text)
	if len == 8 then
		data = data:le_uint64()
	else
		data = data:le_uint()
	end
	st:append_text(_F(": %u", data))
	return st
end

local function add_named_tree_field_int(buf, tree, offset, len, text)
	local data = buf(offset, len)
	local st = tree:add(data, text)
	if len == 8 then
		data = data:le_int64()
	else
		data = data:le_int()
	end
	st:append_text(_F(": %d", data))
	return st
end

local function add_named_tree_field_str(buf, tree, offset, len, text)
	local data = buf(offset, len)
	local st = tree:add(data, text)
	st:append_text(": '" .. data:string() .. "'")
	return st
end

local function add_named_tree_field_strz(buf, tree, offset, len, text)
	local data = buf(offset, len)
	local st = tree:add(data, text)
	st:append_text(": '" .. data:stringz() .. "'")
	return st
end

local function add_named_tree_field_bytes(buf, tree, offset, len, text)
	local data = buf(offset, len)
	local st = tree:add(data, text)
	st:append_text(": " .. data)
	return st
end








	--
	-- Dissection subfunctions
	--


	--
	-- 0x01 - Unknown
	--
	local function disf_01(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- 
		if (is_request(buf)) then
			-- no command data in request

		else
			-- unknown
			add_named_tree_field_bytes(buf, lt, offset_, 16, "Unknown0")
			offset_ = offset_ + 16

			-- device series name?
			add_named_tree_field_strz(buf, lt, offset_, 32, "Controller Model")
			offset_ = offset_ + 32

			add_named_tree_field(buf, lt, offset_, 2, "Unknown1")
			offset_ = offset_ + 2

			add_named_tree_field(buf, lt, offset_, 2, "Unknown2")
			offset_ = offset_ + 2

			-- device model?
			add_named_tree_field_strz(buf, lt, offset_, 32, "Sensor Head Model")
			offset_ = offset_ + 32
		end

		-- nr of bytes we consumed
		return (offset_ - offset)
	end




	--
	-- 0x24 - Auto zero
	--
	local function disf_auto_zero(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- 
		if (is_request(buf)) then
			-- 
			tree_add(lt, f.cmd_24_oper_desig, buf, offset_, 1)
			offset_ = offset_ + 1

			-- 
			tree_add(lt, f.cmd_24_oper_tgt_d_meth, buf, offset_, 1)
			offset_ = offset_ + 1

			-- fixed field 0
			if (config.include_fixed_fields) then
				tree_add(lt, f.cmd_24_fixed0, buf, offset_, 2)
			end
			offset_ = offset_ + 2

			-- 
			tree_add(lt, f.cmd_24_oper_target, buf, offset_, 4)
			offset_ = offset_ + 4

		else
			-- nothing

		end

		-- nr of bytes we consumed
		return (offset_ - offset)
	end




	--
	-- 0x31 - Get Setting
	--
	local function disf_get_setting(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- 
		if (is_request(buf)) then
			-- fixed field 0
			if (config.include_fixed_fields) then
				tree_add(lt, f.cmd_31_fixed0, buf, offset_, 4)
			end
			offset_ = offset_ + 4

			-- level to read (skip next 3)
			tree_add(lt, f.cmd_31_level_to_read, buf, offset_, 1)
			offset_ = offset_ + 4

			-- setting type
			local setting_type = parse_uint(buf, offset_, 1)
			tree_add(lt, f.cmd_31_setting_type, buf, offset_, 1)
			offset_ = offset_ + 1

			-- setting category
			local setting_cat = parse_uint(buf, offset_, 1)
			if (setting_type ~= CMD_31_TYPE_COMMON_SETTINGS) and (setting_type ~= CMD_31_TYPE_ENVIRONMENT_SETTINGS) then
				-- only if 'Type' is neither 'Common Settings' nor 'Environment Settings'
				-- can 'Category' be mapped onto string reps. Otherwise it should be set
				-- to '0' (Sect. 12.1 in the LJ-V7000 Series Communication Library Reference Manual)
				tree_add(lt, f.cmd_31_setting_cat_str, buf, offset_, 1)
			else
				tree_add(lt, f.cmd_31_setting_cat, buf, offset_, 1)
			end
			offset_ = offset_ + 1

			-- setting item
			-- add the field with the right str mapping to the tree
			if (setting_type == CMD_31_TYPE_ENVIRONMENT_SETTINGS) and (setting_cat ~= 0xFF) then
				tree_add(lt, f.cmd_31_setting_item_env, buf, offset_, 1)
			elseif (setting_type == CMD_31_TYPE_COMMON_SETTINGS) and (setting_cat ~= 0xFF) then
				tree_add(lt, f.cmd_31_setting_item_common, buf, offset_, 1)
			else
				-- in all other cases add a non-mapping version
				tree_add(lt, f.cmd_31_setting_item, buf, offset_, 1)
			end
			offset_ = offset_ + 1

			-- reserved
			if (config.include_fixed_fields) then
				tree_add(lt, f.cmd_31_rsvd0, buf, offset_, 1)
			end
			offset_ = offset_ + 1

			-- setting target
			tree_add(lt, f.cmd_31_setting_tgt, buf, offset_, 4)
			offset_ = offset_ + 4

		else
			-- setting value
			local data_len = ctx.body_length - (offset_ - (PFX_LEN + HDR_LEN))
			tree_add(lt, f.cmd_31_setting_val, buf, offset_, data_len)
			offset_ = offset_ + data_len

		end

		-- nr of bytes we consumed
		return (offset_ - offset)
	end




	--
	-- 0x32 - SetSetting
	--
	local function disf_set_setting(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- 
		if (is_request(buf)) then
			-- level to write (skip next 3)
			tree_add(lt, f.cmd_32_level_to_write, buf, offset_, 1)
			offset_ = offset_ + 4

			-- setting type
			tree_add(lt, f.cmd_32_setting_type, buf, offset_, 1)
			offset_ = offset_ + 1

			-- setting category
			tree_add(lt, f.cmd_32_setting_cat, buf, offset_, 1)
			offset_ = offset_ + 1

			-- setting item
			tree_add(lt, f.cmd_32_setting_item, buf, offset_, 1)
			offset_ = offset_ + 1

			-- reserved
			if (config.include_fixed_fields) then
				tree_add(lt, f.cmd_32_rsvd0, buf, offset_, 1)
			end
			offset_ = offset_ + 1

			-- setting target
			tree_add(lt, f.cmd_32_setting_tgt, buf, offset_, 4)
			offset_ = offset_ + 4

			-- setting value
			local data_len = ctx.body_length - (offset_ - (PFX_LEN + HDR_LEN))
			tree_add(lt, f.cmd_32_setting_val, buf, offset_, data_len)
			offset_ = offset_ + data_len

		else
			-- detailed error code
			tree_add(lt, f.cmd_32_detailed_err, buf, offset_, 4)
			offset_ = offset_ + 4

		end

		-- nr of bytes we consumed
		return (offset_ - offset)
	end




	--
	-- 0x33 - ReflectSetting
	--
	local function disf_reflect_setting(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- 
		if (is_request(buf)) then
			-- level to write (skip next 3)
			tree_add(lt, f.cmd_33_reflection_dest, buf, offset_, 1)
			offset_ = offset_ + 4

		else
			-- detailed error code
			tree_add(lt, f.cmd_33_detailed_err, buf, offset_, 4)
			offset_ = offset_ + 4

		end

		-- nr of bytes we consumed
		return (offset_ - offset)
	end




	--
	-- 0x34 - CheckMemoryAccess
	--
	local function disf_check_save_status(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- 
		if (is_request(buf)) then
			-- nothing to do

		else
			-- result (skip next 3)
			tree_add(lt, f.cmd_34_result, buf, offset_, 1)
			offset_ = offset_ + 4

		end

		-- nr of bytes we consumed
		return (offset_ - offset)
	end




	--
	-- 0x39 - Change Active Program number
	--
	local function disf_change_prog_nr(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- 
		if (is_request(buf)) then
			-- program nr (skip next 3)
			tree_add(lt, f.cmd_39_prog_nr, buf, offset_, 1)
			offset_ = offset_ + 4

		else
			-- nothing to do

		end

		-- nr of bytes we consumed
		return (offset_ - offset)
	end




	--
	-- 0x42 - GetProfile (HS mode)
	--
	local function disf_get_profile_hs_mode(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- 
		if (is_request(buf)) then
			if (config.include_fixed_fields) then
				-- fixed field 0
				tree_add(lt, f.cmd_42_fixed0, buf, offset_, 4)
			end
			offset_ = offset_ + 4

			-- set profile get bank
			tree_add(lt, f.cmd_42_profile_bank, buf, offset_, 1)
			offset_ = offset_ + 1

			-- the way of specify to get profile
			tree_add(lt, f.cmd_42_get_profile, buf, offset_, 1)
			offset_ = offset_ + 1

			-- fixed field 1
			if (config.include_fixed_fields) then
				tree_add(lt, f.cmd_42_fixed1, buf, offset_, 2)
			end
			offset_ = offset_ + 2

			-- the number of profile
			tree_add(lt, f.cmd_42_nr_of_profile, buf, offset_, 4)
			offset_ = offset_ + 4

			-- the number of demanded profile
			tree_add(lt, f.cmd_42_nr_demanded_profile, buf, offset_, 1)
			offset_ = offset_ + 1

			-- the number of demanded profile
			tree_add(lt, f.cmd_42_erase_data, buf, offset_, 1)
			offset_ = offset_ + 1

			-- fixed field 2
			if (config.include_fixed_fields) then
				tree_add(lt, f.cmd_42_fixed2, buf, offset_, 2)
			end
			offset_ = offset_ + 2

		-- is a response
		else
			-- profile nr at the current point in time
			tree_add(lt, f.cmd_42_prof_nr_cpit, buf, offset_, 4)
			offset_ = offset_ + 4

			-- The profile number for the oldest profile out of those that were not read this time.
			tree_add(lt, f.cmd_42_prof_nr_oldest_not_read, buf, offset_, 4)
			offset_ = offset_ + 4

			-- The profile number for the oldest profile out of those that were read this time.
			tree_add(lt, f.cmd_42_prof_nr_oldest_read, buf, offset_, 4)
			offset_ = offset_ + 4

			-- number of profiles that were read this time
			local nr_of_profiles_in_pkt = parse_uint(buf, offset_, 1)
			tree_add(lt, f.cmd_42_prof_read, buf, offset_, 1)
			offset_ = offset_ + 1

			-- ignore next 11 bytes
			offset_ = offset_ + 11


			-- if there are no profiles in this packet, we're done
			if (nr_of_profiles_in_pkt == 0) then
				-- total nr of bytes we consumed
				return (offset_ - offset)
			end


			-- TODO: refactor into functions. Multiple dissector subfunctions
			--       can re-use this.

			-- TODO: add proper protocol fields for the following fields

			-- start of profile information
			local profile_info_start = offset_
			local pinfo_tree = lt:add(buf(offset_, 0), "Profile Info Head A")

			local nr_of_points_in_profile = parse_uint(buf, offset_, 2)
			add_named_tree_field(buf, pinfo_tree, offset_, 2, "Nr Of Profile Data")
			offset_ = offset_ + 2

			local pdata_unit = parse_uint(buf, offset_, 2)
			add_named_tree_field(buf, pinfo_tree, offset_, 2, "Profile Data Unit"):append_text(
				_F(" (%.2f μm)", (pdata_unit * 0.01)))
			offset_ = offset_ + 2

			local x_coord = parse_int(buf, offset_, 4)
			add_named_tree_field_int(buf, pinfo_tree, offset_, 4, "First Point X Coordinate"):append_text(
				_F(" (%.2f μm)", (x_coord * 0.01)))
			offset_ = offset_ + 4

			local x_incr = parse_int(buf, offset_, 4)
			add_named_tree_field(buf, pinfo_tree, offset_, 4, "Profile Data X Direction Interval"):append_text(
				_F(" (%.2f μm)", (x_incr * 0.01)))
			offset_ = offset_ + 4

			-- highlight correct nr of bytes we consumed
			pinfo_tree:set_len(offset_ - profile_info_start)




			-- TODO: with TWO HEADS and WIDE OFF this is where profile info would be
			--       for head two
			--       We assume single head here



			for i = 0, (nr_of_profiles_in_pkt - 1) do

				-- create profile tree
				local pdata_start_offset = offset_
				local profile_tree = lt:add(buf(offset_, 0), _F("Profile %d", i))

				-- TODO: decode flag area?
				add_named_tree_field(buf, profile_tree, offset_, 1, "Flag Area")
				offset_ = offset_ + 1

				-- ignore next 3 bytes
				offset_ = offset_ + 3

				-- trigger count
				add_named_tree_field(buf, profile_tree, offset_, 4, "Trigger Count")
				offset_ = offset_ + 4

				-- encoder count
				add_named_tree_field(buf, profile_tree, offset_, 4, "Encoder Count")
				offset_ = offset_ + 4

				if (config.include_fixed_fields) then
					add_named_tree_field_bytes(buf, profile_tree, offset_, 12, "Ignored")
				end
				offset_ = offset_ + 12

				-- start of actual profile data (which we won't dissect here)
				-- 20 bits per point (bpp), packed. So total nr of bytes in profile is:
				--    (bpp * nr_of_points) / 8
				local data_len = ((nr_of_points_in_profile * 20) / 8)

				-- TODO: should all these fields be proper protocol fields?
				--tree_add(profile_tree, f.cmd_42_profile_info, buf, offset_, data_len)

				add_named_tree_field_bytes(buf, profile_tree, offset_, data_len, "Profile Data")
				offset_ = offset_ + data_len

				-- ignored
				-- TODO: is this a checksum?
				if (config.include_fixed_fields) then
					add_named_tree_field(buf, profile_tree, offset_, 4, "Ignored")
				end
				offset_ = offset_ + 4

				-- highlight correct nr of bytes we consumed
				profile_tree:set_len(offset_ - pdata_start_offset)

			end -- per profile dissection

		end -- response end

		-- total nr of bytes we consumed
		return (offset_ - offset)
	end




	--
	-- 0x47 - Profile data high-speed communication preparation
	--
	local function disf_prep_hs_profile_comm(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- 
		if (is_request(buf)) then
			-- start position of sending
			tree_add(lt, f.cmd_47_start_pos, buf, offset_, 1)
			offset_ = offset_ + 4

		else
			-- ignore next 4 bytes
			offset_ = offset_ + 4

			-- start position of sending
			tree_add(lt, f.cmd_47_start_code, buf, offset_, 4)
			offset_ = offset_ + 4

			-- ignore next 8 bytes
			if (config.include_fixed_fields) then
				tree_add(lt, f.cmd_47_ignore0, buf, offset_, 8)
			end
			offset_ = offset_ + 8



			-- TODO: this is a test / kludge
			local head_ctr = 0
			while ((buf:len() - offset_) ~= 0) do

				-- TODO: remove copy, refactor (see 0x42 dissector)

				-- TODO: add proper protocol fields for the following fields

				-- start of profile information
				local profile_info_start = offset_
				local pinfo_tree = lt:add(buf(offset_, 0), _F("Profile Info Head A", string.char(65 + head_ctr)))
				head_ctr = head_ctr + 1

				local nr_of_points_in_profile = parse_uint(buf, offset_, 2)
				add_named_tree_field(buf, pinfo_tree, offset_, 2, "Nr Of Profile Data")
				offset_ = offset_ + 2

				local pdata_unit = parse_uint(buf, offset_, 2)
				add_named_tree_field(buf, pinfo_tree, offset_, 2, "Profile Data Unit"):append_text(
					_F(" (%.2f μm)", (pdata_unit * 0.01)))
				offset_ = offset_ + 2

				local x_coord = parse_int(buf, offset_, 4)
				add_named_tree_field_int(buf, pinfo_tree, offset_, 4, "First Point X Coordinate"):append_text(
					_F(" (%.2f μm)", (x_coord * 0.01)))
				offset_ = offset_ + 4

				local x_incr = parse_int(buf, offset_, 4)
				add_named_tree_field(buf, pinfo_tree, offset_, 4, "Profile Data X Direction Interval"):append_text(
					_F(" (%.2f μm)", (x_incr * 0.01)))
				offset_ = offset_ + 4

				-- highlight correct nr of bytes we consumed
				pinfo_tree:set_len(offset_ - profile_info_start)

			end -- /while

		end

		-- nr of bytes we consumed
		return (offset_ - offset)
	end




	--
	-- 0xA0 - StartHighSpeedDataCommunication
	--
	local function disf_start_profile_data_hs_comm(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- 
		if (is_request(buf)) then
			if (config.include_fixed_fields) then
				-- 0x47 fix
				tree_add(lt, f.cmd_A0_47_fix, buf, offset_, 1)
			end
			offset_ = offset_ + 4

			-- start code
			tree_add(lt, f.cmd_A0_start_code, buf, offset_, 4)
			offset_ = offset_ + 4

		else
			-- no data in response
		end

		-- nr of bytes we consumed
		return (offset_ - offset)
	end




	--
	-- Default parser
	--
	local function disf_default(buf, pkt, tree, offset)
		--
		local offset_ = offset
		local lt = tree

		-- ctx.body_length == total body length, but disf_body(..)
		-- has already dissected a few bits of that. So calculate
		-- the length of whatever is still left to dissect
		-- compensate for length of prefix + header, which
		-- have already been dissected
		local diss_len = ctx.body_length - (offset_ - (PFX_LEN + HDR_LEN))

		if (diss_len > 0) then
			lt:add(buf(offset_, diss_len), _F("Undissected (%u bytes)", diss_len))
			offset_ = offset_ + diss_len
		end

		if (diss_len < 0) then
			lt:add_expert_info(PI_DEBUG, PI_NOTE, _F("diss_len: %d", diss_len))
		end

		-- nr of bytes we consumed
		return (offset_ - offset)
	end




	--
	-- message type -> dissection function map
	--
	local map_cmd_code_to_disf = {
		[CMD_UNKNOWN_0x01                    ] = disf_01,
		[CMD_AUTO_ZERO                       ] = disf_auto_zero,
		[CMD_GET_SETTING                     ] = disf_get_setting,
		[CMD_SET_SETTING                     ] = disf_set_setting,
		[CMD_REFLECT_SETTING                 ] = disf_reflect_setting,
		[CMD_CHECK_SAVE_STATUS               ] = disf_check_save_status,
		[CMD_CHANGE_PROGRAM                  ] = disf_change_prog_nr,
		[CMD_GET_PROFILE_HIGHSPEED_MODE      ] = disf_get_profile_hs_mode,
		[CMD_PREPARE_HIGH_SPEED_PROFILE_COMM ] = disf_prep_hs_profile_comm,
		[CMD_START_HIGH_SPEED_PROFILE_COMM   ] = disf_start_profile_data_hs_comm,
	}




	local function disf_prefix(buf, pkt, tree, offset)
		local offset_ = offset
		local lt = tree

		-- Prefix: only header + body length
		local pfx_tree = lt:add(buf(offset_, 0), "Prefix")

		-- extract packet length
		tree_add(pfx_tree, f.pfx_hdr_len, buf, offset_, 4)
		offset_ = offset_ + 4

		-- highlight the correct nr of bytes
		local tlen = offset_ - offset
		pfx_tree:set_len(tlen)
		return (tlen)
	end


	local function disf_header(buf, pkt, tree, offset)
		local offset_ = offset
		local lt = tree

		-- Header: version, etc
		local hdr_tree = lt:add(buf(offset_, 0), "Header")

		-- version?
		tree_add(hdr_tree, f.hdr_version, buf, offset_, 2)
		offset_ = offset_ + 2

		-- request / response field
		tree_add(hdr_tree, f.hdr_reqresp, buf, offset_, 2)
		offset_ = offset_ + 2

		-- 
		if (is_request(buf)) then
			-- ignore next 4 bytes (all zeros)
			offset_ = offset_ + 4
		else
			tree_add(hdr_tree, f.hdr_ret_code, buf, offset_, 1)
			offset_ = offset_ + 4
		end

		-- body length
		body_length = parse_uint(buf, offset_, 4)
		tree_add(hdr_tree, f.hdr_body_len, buf, offset_, 4)
		offset_ = offset_ + 4

		-- store in context for this pkt (used by body dissector functions)
		ctx.body_length = body_length

		-- highlight the correct nr of bytes
		local tlen = offset_ - offset
		hdr_tree:set_len(tlen)
		return (tlen)
	end


	local function disf_body(buf, pkt, tree, offset)
		local offset_ = offset
		local lt = tree

		-- Body
		local body_tree = lt:add(buf(offset_, 0), "Body")
		local btree_offset = offset_

		-- command code
		local cmd_code = parse_uint(buf, offset_, 1)
		tree_add(body_tree, f.body_cmd_code, buf, offset_, 1)
		offset_ = offset_ + 1

		-- dissect common 'body parts'
		if (is_request(buf)) then
			-- ignore next 3 bytes
			offset_ = offset_ + 3
		else
			-- return code
			tree_add(body_tree, f.body_ret_code, buf, offset_, 1)
			offset_ = offset_ + 1

			-- controller status
			tree_add(body_tree, f.body_ctrlr_status, buf, offset_, 1)
			offset_ = offset_ + 1

			-- ignore next 5 bytes
			offset_ = offset_ + 5

			-- active program no
			tree_add(body_tree, f.body_act_prog_nr, buf, offset_, 1)
			offset_ = offset_ + 1

			-- ignore next 3 bytes
			offset_ = offset_ + 3
		end

		-- highlight the correct nr of bytes
		body_tree:set_len(offset_ - btree_offset)

		-- now do command specific dissection (we've
		-- stored the cmd_code when body_cmd_code field
		-- was added to the dissection tree), but only if
		-- there are still bytes to dissect
		if ((buf:len() - offset_) ~= 0) then
			local diss_f = map_cmd_code_to_disf[cmd_code] or disf_default

			-- Command Data tree
			local cmdd_tree = body_tree:add(buf(offset_, 0), "Command Data")

			-- dissect using the function
			local cmdd_offset = offset_
			offset_ = offset_ + diss_f(buf, pkt, cmdd_tree, offset_)

			-- highlight the correct nr of bytes
			--   for the 'command data' tree
			local tlen = offset_ - cmdd_offset
			cmdd_tree:set_len(tlen)
		end

		-- highlight the correct nr of bytes
		--   for the 'body' tree
		tlen = offset_ - offset
		body_tree:set_len(tlen)
		return (tlen)
	end


	--
	-- main parser function
	--
	local function parse(buf, pkt, tree, offset)
		local offset_ = offset
		local lt = tree

		offset_ = offset_ + disf_prefix(buf, pkt, lt, offset_)

		offset_ = offset_ + disf_header(buf, pkt, lt, offset_)

		offset_ = offset_ + disf_body(buf, pkt, lt, offset_)

		-- highlight the correct nr of bytes
		local tlen = offset_ - offset
		lt:set_len(tlen)
		return (tlen)
	end


	--
	-- actual dissector method
	--
	function p_keyence_ljv7k_tcp.dissector(buf, pkt, tree)
		-- check pkt len
		local buf_len = buf:len()
		if (buf_len <= 0) then return end

		-- either we resume dissecting, or we start fresh
		local offset = pkt.desegment_offset or 0

		-- keep dissecting as long as there are bytes available
		while true do
			-- get packet length
			local pkt_len = parse_pkt_len(buf, offset)

			-- TODO: add some sanity check on packet length?

			-- add length prefix to it
			pkt_len = pkt_len + 4

			-- make sure we have enough for coming packet. If not, signal
			-- caller by setting appropriate fields in 'pkt' argument
			local nextpkt = offset + pkt_len
			if (nextpkt > buf_len) then
				pkt.desegment_len = nextpkt - buf_len
				pkt.desegment_offset = offset
				return
			end

			-- have enough data: add protocol to tree
			local subtree = tree:add(p_keyence_ljv7k_tcp, buf(offset, pkt_len))

			-- create string repr of packet type
			local cmd_code  = parse_cmd_code(buf, offset)
			local cmd_c_str = str_or_none(cmd_code_str, cmd_code)

			-- add some extra info to the protocol line in the packet treeview
			local rr_str = "Request"
			if (is_response(buf)) then rr_str = "Response" end
			subtree:append_text(_F(", %s (0x%02x), %s, %u bytes",
				cmd_c_str, cmd_code, rr_str, pkt_len))

			-- add info to top pkt view
			pkt.cols.protocol = p_keyence_ljv7k_tcp.name

			-- use offset in buffer to determine if we need to append to or set
			-- the info column
			if (offset > 0) then
				pkt.cols.info:append(_F(", %s (0x%02x, %s)", cmd_c_str, cmd_code, rr_str))
			else
				pkt.cols.info = _F("%s (0x%02x, %s)", cmd_c_str, cmd_code, rr_str)
			end

			-- dissect rest of pkt
			local res = parse(buf, pkt, subtree, offset)

			-- increment 'read pointer' and stop if we've dissected all bytes
			-- in the buffer
			offset = nextpkt
			if (offset == buf_len) then return end

		-- end-of-dissect-while
		end

	-- end-of-dissector
	end




	--
	-- init routine
	--
	function p_keyence_ljv7k_tcp.init()
		-- update config from prefs
		config.include_fixed_fields = p_keyence_ljv7k_tcp.prefs["include_fixed_fields"]
	end




	--
	-- register dissector
	--
	local tcp_dissector_table = DissectorTable.get("tcp.port")

	-- TODO: make ports to register dissector on configurable via preferences
	-- default keyence ethernet port
	tcp_dissector_table:add(DEFAULT_KEYENCE_PORT, p_keyence_ljv7k_tcp)
end
