import type * as React from 'react';

type Tone = 'ink' | 'paper';

/** The wordmark, set in Jost Medium, always lowercase. */
export interface WordmarkProps { size?: number; tone?: Tone; className?: string }
export declare function Wordmark(props: WordmarkProps): React.ReactElement;

/** The dot: the brand mark. Decorative unless `label` is given. */
export interface MarkProps { size?: number; tone?: Tone; label?: string; className?: string }
export declare function Mark(props: MarkProps): React.ReactElement;

/** The tide line: hops that grow into a wave, with the dot at its head. */
export interface TideProps {
  width?: number; height?: number;
  /** Number of wave periods along the line. Default 2.25. */
  periods?: number;
  /** Wave height as a fraction of the cross size. Default 0.38. */
  amplitude?: number;
  /** Start with fading hops (|sin|) that become the wave. Default true. */
  hops?: boolean;
  /** Flatten the last stretch into a still line: the rewind, everything back to calm. Default false. */
  calm?: boolean;
  /** 'vertical' fits tall, narrow spaces: the wave above, the dot at the bottom. */
  orientation?: 'horizontal' | 'vertical';
  dot?: boolean; stroke?: number; tone?: Tone; label?: string; id?: string; className?: string;
}
export declare function Tide(props: TideProps): React.ReactElement;

/** A headline with the one line that explains it. */
export interface MessageProps {
  title: React.ReactNode; children?: React.ReactNode; align?: 'center' | 'start';
  /** A Status line under the message, e.g. on a crest of the tide. */
  status?: React.ReactNode; className?: string;
}
export declare function Message(props: MessageProps): React.ReactElement;

/** One sentence alone on screen. */
export interface StatementProps { children: React.ReactNode; className?: string }
export declare function Statement(props: StatementProps): React.ReactElement;

/** Where a part of the product stands. `built` only when it has passing tests. */
export interface StatusProps {
  state: 'built' | 'progress' | 'next';
  /** Replaces the state's words ("Built and tested", "In progress", "Next"), e.g. in Spanish. */
  label?: string;
  /** How it is solved, in one short sentence. */
  children?: React.ReactNode; className?: string;
}
export declare function Status(props: StatusProps): React.ReactElement;

/** The dot as a button: a 44px ink circle with an arrow. `label` is required for screen readers. */
export interface DotButtonProps { label: string; type?: 'button' | 'submit'; onClick?: React.MouseEventHandler<HTMLButtonElement>; disabled?: boolean; className?: string }
export declare function DotButton(props: DotButtonProps): React.ReactElement;

/** A field: label, text, one hairline. `action` sits at the end of the line (e.g. a DotButton). */
export interface TextFieldProps {
  id: string; label?: string; name?: string; type?: string; placeholder?: string; autoComplete?: string;
  inputMode?: React.HTMLAttributes<HTMLInputElement>['inputMode'];
  value?: string; defaultValue?: string; onChange?: React.ChangeEventHandler<HTMLInputElement>;
  required?: boolean; action?: React.ReactNode; className?: string;
}
export declare function TextField(props: TextFieldProps): React.ReactElement;

/** The waitlist form. `onSubmit(email, setStatus)` sends the address and reports back with setStatus({ text, error? }). */
export interface EmailCaptureProps {
  id?: string; label?: string; placeholder?: string; submitLabel?: string;
  info?: string; privacyHref?: string; privacyLabel?: string; invalidText?: string;
  onSubmit?: (email: string, setStatus: (status: { text: string; error?: boolean } | null) => void) => void;
  className?: string;
}
export declare function EmailCapture(props: EmailCaptureProps): React.ReactElement;

/** Footer of every public page: legal links and the language switch. */
export interface LegalFooterProps {
  links?: { label: string; href: string }[];
  languages?: string[]; current?: string; onLanguage?: (code: string) => void; languageLabel?: string;
  /** A hairline above, for document pages. */
  ruled?: boolean; className?: string;
}
export declare function LegalFooter(props: LegalFooterProps): React.ReactElement;

/** A document page: home link, title, date, sections and an optional footer. */
export interface DocumentProps {
  title: React.ReactNode; updated?: React.ReactNode; homeHref?: string;
  sections?: { heading: React.ReactNode; body: React.ReactNode }[];
  children?: React.ReactNode; footer?: React.ReactNode; className?: string;
}
export declare function Document(props: DocumentProps): React.ReactElement;

declare global {
  interface Window {
    Backtide: {
      Wordmark: typeof Wordmark; Mark: typeof Mark; Tide: typeof Tide; Message: typeof Message; Statement: typeof Statement; Status: typeof Status;
      DotButton: typeof DotButton; TextField: typeof TextField; EmailCapture: typeof EmailCapture; LegalFooter: typeof LegalFooter; Document: typeof Document;
    };
  }
}
