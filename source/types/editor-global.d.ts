declare const Editor: {
  Project: {
    path: string;
    name?: string;
  };
  Panel: {
    open(name: string): Promise<void> | void;
  };
  Message: {
    request(pkg: string, method: string, ...args: any[]): Promise<any>;
    send?(pkg: string, message: string, ...args: any[]): void;
  };
};
