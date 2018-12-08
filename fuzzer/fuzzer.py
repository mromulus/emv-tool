# This Python file uses the following encoding: utf-8
# Native
import sys
import logging
import datetime
from timeit import default_timer as timer
from time import sleep
import random

# 3rd party (PyScard)
from smartcard.sw.ISO7816_4ErrorChecker import ISO7816_4ErrorChecker
from smartcard.sw.ISO7816_8ErrorChecker import ISO7816_8ErrorChecker
from smartcard.sw.ISO7816_9ErrorChecker import ISO7816_9ErrorChecker
from smartcard.sw.ErrorCheckingChain import ErrorCheckingChain
from smartcard.sw.SWExceptions import SWException
from smartcard.Exceptions import CardConnectionException, NoCardException

# LL Smartcard
import llsmartcard.apdu as APDU
from llsmartcard.apdu import APDU_STATUS, APPLET
from llsmartcard.card import SmartCard, CAC

# Setup our error chain
errorchain = []
errorchain = [ErrorCheckingChain(errorchain, ISO7816_9ErrorChecker()),
              ErrorCheckingChain(errorchain, ISO7816_8ErrorChecker()),
              ErrorCheckingChain(errorchain, ISO7816_4ErrorChecker())]

# List of valid classes and insructions
valid_cla = []
valid_ins = []

# Hash tables to help aggregate findings
cla_sw_ins = {}
sw_ins_cla = {}


# What values do we consider a success?
SUCCESS_LIST = [0x90,  # Success
                0x61,  # More Data
                0x67,  # Wrong Length
                0x6c,  # Wrong Length
                0x6a,  # Referenced Data not found
                # 0x69 # Access Violation (Not sure about this)
                ]

SUCCESS_BAD_PARAM = [(0x6a, 0x86)  # Incorrect Paramters
                     ]
SUCCESS_FAIL = [(0x6a, 0x81),  # Function not supported
                # (0x6a, 0x88) # Referenced data not found
                ]



SUCCESS_LIST_FOR_SPECIFIC = [0x90,0x61]

now = datetime.datetime.now()
CDOL_FIELDS = {
  '9F02': [0x0, 0x0, 0x0, 0x0, 0x0, 0x1], # 0.01€ (amount authorized) 6 bytes
  '9F03': [0x0, 0x0, 0x0, 0x0, 0x0, 0x0], # (amount other) 6 bytes
  '9F1A': [0x02, 0x33], # Estonia (terminal country code) 2 bytes
  '95': [0x80, 0x00, 0x00, 0x00, 0x80], # (TVR - Terminal Verification Results) 5 bytes
  '5F2A': [0x09, 0x78], # Euro (terminal currency code) 2 bytes
  '9A': [int(str(now.year-2000), 16), int(str(now.month), 16), int(str(now.day), 16)], # (transaction date) 3 bytes
  '9C': [0x0], # (transaction type) 1 bytes
  '9F37': [0x0] * 4, # (unpredictable number) 4 bytes
  '9F35': [0x21], # (terminal type) 1 bytes
  '9F45': [0x0] * 2, # (data authentication code) 2 bytes
  '9F4C': [0x0] * 8, # (ICC dynamic number) 8 bytes
  '9F34': [0x1F, 0x03, 0x02], # (CVM Results - Cardholder Verification Results) 3 bytes
  '9F21': [int(str(now.hour)), int(str(now.minute)), int(str(now.second))], # (transaction time) 3 bytes
  '9F7C': [0x0] * 20 # (?) 20 bytes
}

def insert_success(cla, ins, p1, p2, sw1, sw2, time, data=None):
    """
        Insert a succesful response into our valid list
    """
    global valid_ins
    valid_ins.append((cla, ins, (p1, p2), (sw1, sw2), time, data))
    successful_apdu = "%04s %04s %04s %04s %04s %04s" % (hex(cla),
                                                         hex(ins),
                                                         hex(p1),
                                                         hex(p2),
                                                         hex(sw1),
                                                         hex(sw2)
                                                         )
    print "Got Success: %s in %f ms" % (successful_apdu, time*1000)


def insert_trial(cla, ins, sw1, sw2):
    """
        Insert a trial with status word response into our structures
    """
    global cla_sw_ins, sw_ins_cla

    sw = sw1 << 8 | sw2

    # Depth = 1
    if cla not in cla_sw_ins:
        cla_sw_ins[cla] = {}
    if sw not in sw_ins_cla:
        sw_ins_cla[sw] = {}

    # Depth = 2
    if ins not in sw_ins_cla[sw]:
        sw_ins_cla[sw][ins] = []
    if ins not in cla_sw_ins[cla]:
        cla_sw_ins[cla][sw] = []

    # Add the nugget
    sw_ins_cla[sw][ins].append(cla)
    cla_sw_ins[cla][sw].append(ins)


"""
    Functions to handle output
"""


def open_file(filename):
    """
        Open the given filename for writing or default to standard out
    """
    if filename is None:
        output = sys.stdout
    else:
        try:
            output = open(filename, "w+")
        except:
            logging.error("Couldn't open %s." % filename)
            output = sys.stdout

    return output


def print_cla_sw_ins(filename=None):
    """
        Print CLAss, Status Word, INStruction into a tab-delimited file
    """
    output = open_file(filename)

    output.write("%04s\t%06s\t%s\n" % ("CLA", "SW", "INS(s)"))
    for cla in cla_sw_ins:
        for sw in cla_sw_ins[cla]:
            output.write("%04s\t%06s\t" % (hex(cla), hex(sw)))
            for ins in cla_sw_ins[cla][sw]:
                output.write("%s " % hex(ins))
            output.write("\n")

    if output != sys.stdout:
        output.close()


def print_sw_ins_cla(filename=None):
    """
        Print Status Word, INStruction, CLAss into a tab-delimited file
    """
    output = open_file(filename)

    output.write("%06s\t%04s\t%s\n" % ("SW", "INS", "CLA(s)"))
    for sw in sw_ins_cla:
        for ins in sw_ins_cla[sw]:
            output.write("%06s\t%04s\t" % (hex(sw), hex(ins)))
            for cla in sw_ins_cla[sw][ins]:
                output.write("%s " % hex(cla))
            output.write("\n")

    if output != sys.stdout:
        output.close()


def print_success(filename=None):
    """
        Print all successful responses to filename
    """

    output = open_file(filename)

    output.write("%04s %04s %04s %04s %04s %04s\n" %
                 ("CLA", "INS", "P1", "P2", "SW1", "SW2"))

    for valid in valid_ins:
        (cla, ins, (p1, p2), (sw1, sw2), time, data) = valid
        successful_apdu = "%04s %04s %04s %04s %04s %04s %f %s" % (hex(cla),
                                                             hex(ins),
                                                             hex(p1),
                                                             hex(p2),
                                                             hex(sw1),
                                                             hex(sw2),
                                                             time,
                                                             data
                                                             )
        output.write(successful_apdu + "\n")

    if output != sys.stdout:
        output.close()

def print_results():
    print "Found %d valid instructions." % len(valid_ins)

    print "Saving results..."

    print_cla_sw_ins("cla_sw_ins.tsv")
    print_sw_ins_cla("sw_ins_cla.tsv")
    print_success("successes.txt")

    print "Done."

class Fuzzer:
  def __init__(self, reader, logical_channel):
    self.reader = reader
    self.logical_channel = logical_channel
    self.get_card()
    if self.logical_channel > 0:
      self.card._send_apdu([0x0, 0x70, 0x0] + [self.logical_channel])

  def get_card(self):
    # create connection
    if hasattr(self, 'connection'):
      self.connection.disconnect();

    self.connection = self.reader.createConnection()
    self.connection.connect()

    self.card = SmartCard(self.connection)

  def select(self, application):
    self.card._send_apdu([0+self.logical_channel, 0xA4, 0x04, 0x00] + [len(application)] + application + [0x00])

  def send_channel_aware_precommand(self, command):
    apdu = command
    apdu[0] += self.logical_channel
    self.card._send_apdu(apdu)

  def send_apdu(self, apdu_to_send):
      """
          Send an APDU to the card, and hadle errors appropriately
      """
      str = "Trying : ", [hex(i) for i in apdu_to_send]
      logging.debug(str)
      start = timer()
      try:
        for attempt in range(10):
          try:
            (data, sw1, sw2) = self.card._send_apdu(apdu_to_send)
            errorchain[0]([], sw1, sw2)
          except CardConnectionException, e:
            sleep(1)
            self.get_card();
          else:
            break
        else:
          raise CardConnectionException

      except SWException, e:
          # Did we get an unsuccessful attempt?
          logging.info(e)
      except CardConnectionException, e:
          logging.info(e)
          print("Card removed from reader, exiting");
          sys.exit();
      except NoCardException:
        print("Card removed from reader, exiting");
        print_results();
        sys.exit();
      except e:
          logging.warn("Oh No! Pyscard crashed...")
          logging.info(e)
          (data, sw1, sw2) = ([], 0xFF, 0xFF)

      end = timer()
      str = "Got : ", data, hex(sw1), hex(sw2), "in ", (end-start)*1000, "ms"
      logging.debug(str)

      return (data, sw1, sw2, (end-start))



  def enumerate_classes(self):
    # First, determine all possible valid command classes
      print "Enumerating valid classes..."
      for cla in range(0xFF + 1):
          # CLS INS P1 P2
          apdu_to_send = [cla, 0xa4, 0x00, 0x00]

          (data, sw1, sw2, time) = self.send_apdu(apdu_to_send)

          # unsupported class is 0x6E00
          if (sw1 == 0x6E) and (sw2 == 0x00):
              continue
          else:
              valid_cla.append(cla)

      # Print our valid classes
      print "Found %d valid command classes: " % len(valid_cla),
      for cla in valid_cla:
          print "%s" % hex(cla),
      print ""

  def test_command(self, cla, ins, p1, p2):
    # Try our best not to lock up the card
    BAD_INSTRUCTIONS = [APDU.APDU_CMD.VERIFY, APDU.APDU_CMD.CHANGE_REF_DATA]

    if ins in BAD_INSTRUCTIONS:
      return

    # CLS INS P1 P2
    apdu_to_send = [cla, ins, p1, p2]

    # Send APDU
    (data, sw1, sw2, time) = self.send_apdu(apdu_to_send)

    # Success?
    if sw1 in SUCCESS_LIST:
        if (sw1, sw2) not in SUCCESS_FAIL:
            insert_success(cla, ins, p1, p2, sw1, sw2, time)

    # Add response to hash tables
    insert_trial(cla, ins, sw1, sw2)

  def map_commands(self, args=None):
      """
          Enumerate all valid classes, and brute force all instructions on those
          classes, recording the results
      """

      self.enumerate_classes();
      # Next, try all possible instruction values for each valid command class
      print "Brute forcing every command for each class..."
      for cla in valid_cla:
          for ins in range(0xFF + 1):
              self.test_command(cla, ins, 0x00, 0x00)


      print_results();

  def fuzz_params(self, command, length=0):
    (cla, ins) = command

    print "Brute forcing command %04s %04s" % (hex(cla), hex(ins))
    # Brute force Parameters
    for p1 in range(0xff + 1):
       for p2 in range(0xff + 1):

          # CLS INS P1 P2
          apdu_to_send = [cla, ins, p1, p2]

          if length>0:
            apdu_to_send += [length] + random.sample(range(0, 255), length) + [0x0]

          # Send APDU
          (data, sw1, sw2, time) = self.send_apdu(apdu_to_send)

          # Check status
          if sw1 in SUCCESS_LIST_FOR_SPECIFIC:
            insert_success(cla, ins, p1, p2, sw1, sw2, time, data)


    print_results();


  def fuzz_payload(self, command, p1, p2, length=0, max_tries=5000):
    (cla, ins) = command

    print "Brute forcing command %04s %04s with p1 %04s, p2 %04s" % (hex(cla), hex(ins), hex(p1), hex(p2))

    tries = 0

    while len(valid_ins) == 0 or tries < max_tries:
      # CLS INS P1 P2
      apdu_to_send = [cla, ins, p1, p2] + [length]
      for byte in range(length):
        apdu_to_send += [random.randrange(0,255)]

      apdu_to_send += [0x0]

      # Send APDU
      (data, sw1, sw2, time) = self.send_apdu(apdu_to_send)

      # Check status
      if sw1 in SUCCESS_LIST_FOR_SPECIFIC:
        insert_success(cla, ins, p1, p2, sw1, sw2, time, data)

      tries += 1


    print_results();

  def mutation_fuzz(self, command, p1, p2, payload, pre_command, use_random=True):
    (cla, ins) = command

    current_payload = payload

    print "Mutation fuzzing"
    for attempt in range(15000):
      for attempt in range(random.randrange(3,10)):
        random_index = random.randrange(0,len(current_payload))
        current_payload[random_index] = max(0, min(255, current_payload[random_index] + random.randrange(-64, 64)))

      random_addition = []
      if use_random:
        for count in range(random.randrange(300,500)):
          random_addition = random_addition + [random.randrange(0,255)]

      # CLS INS P1 P2
      apdu_to_send = [cla, ins, p1, p2] + [len(current_payload)] + current_payload + random_addition + [0x0]
      (data, sw1, sw2, time) = self.send_apdu(apdu_to_send)

      # Check status - looking for errors
      if sw1 not in SUCCESS_LIST_FOR_SPECIFIC:
        insert_success(cla, ins, p1, p2, sw1, sw2, time, data)

      if pre_command:
        # run pre-command to reset state
        self.send_channel_aware_precommand(pre_command)
        self.send_channel_aware_precommand(pre_command)

    print_results();
