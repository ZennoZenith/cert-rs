export type Subscriber<T> = (value: T) => void;

export class Signal<T> {
  private _value: T;
  private subscribers: Set<Subscriber<T>> = new Set();

  constructor(initialValue: T) {
    this._value = initialValue;
  }

  get value(): T {
    return this._value;
  }

  set value(newValue: T) {
    if (newValue !== this._value) {
      // Only notify if the value actually changed
      this._value = newValue;
      this.notifySubscribers();
    }
  }

  subscribe(subscriber: Subscriber<T>): void {
    this.subscribers.add(subscriber);
  }

  unsubscribe(subscriber: Subscriber<T>): void {
    this.subscribers.delete(subscriber);
  }

  private notifySubscribers(): void {
    this.subscribers.forEach((subscriber) => subscriber(this._value));
  }
}

// // Usage example:
// const mySignal = new Signal<number>(0);

// mySignal.subscribe((newValue) => {
//   console.log(`Signal value changed to: ${newValue}`);
// });

// mySignal.value = 10; // This will log: "Signal value changed to: 10"
// mySignal.value = 10; // This will not log anything as the value didn't change
// mySignal.value = 20; // This will log: "Signal value changed to: 20"
