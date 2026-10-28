// Derived from minexew/Shrine (Unlicense, see LICENSE-Shrine.txt); local changes are listed in PATCHES.md.
U0 HandleNetFifoEntry(CNetFifoEntry* e) {
  CEthFrame l2_frame;

  if (EthernetFrameParse(&l2_frame, e->frame, e->length) < 0)
    return;


  CL3Protocol* l3 = l3_protocols;

  while (l3) {
    if (l3->ethertype == l2_frame.ethertype) {
      l3->handler(&l2_frame);
      break;
    }
    l3 = l3->next;
  }
}

U0 NetHandlerTask(I64) {
  EthernetInit();

  while (1) {
    CNetFifoEntry* e = NetFifoPull();

    if (e) {
      HandleNetFifoEntry(e);
    }
    else {
      LBts(&Fs->task_flags, TASKf_IDLE);
      Yield;
    }
  }
}

