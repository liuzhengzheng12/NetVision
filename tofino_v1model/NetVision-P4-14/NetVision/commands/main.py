import pd_base_tests
import pltfm_pm_rpc
import pal_rpc

from ptf import config
from ptf.testutils import *
from ptf.thriftutils import *
from pltfm_pm_rpc.ttypes import *
from pal_rpc.ttypes import *
from res_pd_rpc.ttypes import *
from netvision.p4_pd_rpc.ttypes import *


INSTANCE_NAME = 'netvision'

fp_ports = ['1/0','2/0','3/0','4/0','5/0','6/0','7/0','8/0','9/0','10/0']
port_dict = {
    1 : 128,
    2 : 136,
    3 : 144,
    4 : 152,
    5 : 160,
    6 : 168,
    7 : 176,
    8 : 184,
    9 : 60,
    10 : 52
}

class NetVision_Test(pd_base_tests.ThriftInterfaceDataPlane):
    def __init__(self):
        pd_base_tests.ThriftInterfaceDataPlane.__init__(self, [INSTANCE_NAME])
        self.instance_name = INSTANCE_NAME

    def setUp(self):
        pd_base_tests.ThriftInterfaceDataPlane.setUp(self)

        self.sess_hdl = self.conn_mgr.client_init()
        self.dev_tgt  = DevTarget_t(0, hex_to_i16(0xFFFF))
        self.devPorts = []

        self.platform_type = "mavericks"
        board_type = self.pltfm_pm.pltfm_pm_board_type_get()
        if re.search("0x0234|0x1234|0x4234|0x5234", hex(board_type)):
            self.platform_type = "mavericks"
        elif re.search("0x2234|0x3234", hex(board_type)):
            self.platform_type = "montara"

        # get the device ports from front panel ports
        try:
            for fpPort in fp_ports:
                port, chnl = fpPort.split("/")
                devPort = \
                    self.pal.pal_port_front_panel_port_to_dev_port_get(0,
                                                                    int(port),
                                                                    int(chnl))
                self.devPorts.append(devPort)

            if test_param_get('setup') == True or (test_param_get('setup') != True
                and test_param_get('cleanup') != True):

                # add and enable the platform ports
                for i in self.devPorts:
                    self.pal.pal_port_add(0, i,
                                        pal_port_speed_t.BF_SPEED_40G,
                                        pal_fec_type_t.BF_FEC_TYP_NONE)
                    self.pal.pal_port_enable(0, i)
                self.conn_mgr.complete_operations(self.sess_hdl)
        except Exception as e:
            print "Some Error in port init"
        print self.devPorts

    def runTest(self):
        print 'Test start.'

        self.cleanUpTables()
        self.setUpEntries()

        print 'Test done.'

    def setUpEntries(self):
        print 'setup entries start.'
        self.setUpforward()
        print 'setup entries done.'

    def setUpforward(self):
        table_name = 'forward'
        action_name = 'set_egress_port'

        self.addEntry(table_name, action_name, [port_dict[1]], [port_dict[3]])
        self.addEntry(table_name, action_name, [port_dict[4]], [port_dict[5]])
        self.addEntry(table_name, action_name, [port_dict[6]], [port_dict[7]])
        self.addEntry(table_name, action_name, [port_dict[8]], [port_dict[9]])
        self.addEntry(table_name, action_name, [port_dict[10]], [port_dict[2]])
        self.addEntry(table_name, action_name, [port_dict[2]], [port_dict[1]])

    def tearDown(self):
        #self.cleanUpTables()
        pass

    def cleanUpTables(self):
        print 'cleanup entries start.'
        self.cleanUpTable("forward")
        print 'cleanup entries done.'

    def addEntry(self, table_name, action_name, match_fields, action_parameters, priority = None):
        self.entries={}
        self.entries[self.instance_name] = []   

        match = eval(self.instance_name + '_' +
                     table_name +
                     '_match_spec_t')(*match_fields)
        if priority is None:
            if isinstance(action_parameters, int):
                self.entries[self.instance_name].append(
                    eval('self.client.' + table_name + '_table_add_with_' + action_name)(
                        self.sess_hdl, self.dev_tgt, match, action_parameters))
            elif len(action_parameters) == 0:
                    self.entries[self.instance_name].append(
                    eval('self.client.' + table_name + '_table_add_with_' + action_name)(
                        self.sess_hdl, self.dev_tgt, match))
            else:
                action = eval(self.instance_name + '_' +
                            action_name +
                            '_action_spec_t')(*action_parameters)
    
                self.entries[self.instance_name].append(
                    eval('self.client.' + table_name + '_table_add_with_' + action_name)(
                        self.sess_hdl, self.dev_tgt, match, action))
        else:
            if isinstance(action_parameters, int):
                self.entries[self.instance_name].append(
                    eval('self.client.' + table_name + '_table_add_with_' + action_name)(
                        self.sess_hdl, self.dev_tgt, match, action_parameters, priority))
            elif len(action_parameters) == 0:
                self.entries[self.instance_name].append(
                    eval('self.client.' + table_name + '_table_add_with_' + action_name)(
                        self.sess_hdl, self.dev_tgt, match, priority))
            else:
                action = eval(self.instance_name + '_' +
                            action_name +
                            '_action_spec_t')(*action_parameters)
    
                self.entries[self.instance_name].append(
                    eval('self.client.' + table_name + '_table_add_with_' + action_name)(
                        self.sess_hdl, self.dev_tgt, match, action, priority))

        self.conn_mgr.complete_operations(self.sess_hdl)

    def setDefaultEntry(self, table_name, action_name, action_parameters):
        if len(action_parameters) == 0:
            eval('self.client.' + table_name + 
                 '_set_default_action_' + action_name)(self.sess_hdl, self.dev_tgt)
        else:
            action_spec = eval(self.instance_name + '_' + 
                           action_name + 
                           '_action_spec_t')(*action_parameters)
            eval('self.client.' + table_name + 
                 '_set_default_action_' + action_name)(self.sess_hdl, self.dev_tgt, action_spec)
        self.conn_mgr.complete_operations(self.sess_hdl)

    def cleanUpTable(self, table_name):
        table_name = 'self.client.' + table_name
        num_entries = eval(table_name + '_get_entry_count')\
                      (self.sess_hdl, self.dev_tgt)
        print "Number of entries : {}".format(num_entries)
        if num_entries == 0:
            return
        # get the entry handles
        hdl = eval(table_name + '_get_first_entry_handle')\
                (self.sess_hdl, self.dev_tgt)
        if num_entries > 1:
            hdls = eval(table_name + '_get_next_entry_handles')\
                (self.sess_hdl, self.dev_tgt, hdl, num_entries - 1)
            hdls.insert(0, hdl)
        else:
            hdls = [hdl]
        # delete the table entries
        for hdl in hdls:
            entry = eval(table_name + '_get_entry')\
                (self.sess_hdl, self.dev_tgt.dev_id, hdl, True)
            eval(table_name + '_table_delete')\
                (self.sess_hdl, self.dev_tgt.dev_id, hdl)
