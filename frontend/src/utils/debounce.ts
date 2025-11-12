export class Debounce {
  private timeout: ReturnType<typeof setTimeout> | undefined;
  private waitTime: number;

  constructor(wait: number = 300) {
    this.waitTime = wait;
  }

  debounce = (callback: Function, wait?: number) => {
    wait ??= this.waitTime;
    return (...args: any[]) => {
      clearTimeout(this.timeout);
      this.timeout = setTimeout(() => callback(...args), wait);
    };
  };

  debounceAsync = (callback: Function, wait?: number) => {
    wait ??= this.waitTime;
    return (...args: any[]) => {
      clearTimeout(this.timeout);
      this.timeout = setTimeout(async () => await callback(...args), wait);
    };
  };
}
