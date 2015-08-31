struct ops {
  void (*register_cmd)(unsigned int opcode, unsigned int flags, void *(*fp)(void *));
  void (*unregister_cmd)(unsigned int opcode);
};

int parse_pak(unsigned char *pakaddr, size_t paklen, size_t base, struct ops *ops);
