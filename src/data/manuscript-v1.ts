import { BookVersionData } from '../types.ts';
import { FRONTMATTER_SECTIONS } from './manuscript/frontmatter.ts';
import { CHAPTER_ONE } from './manuscript/chapter1.ts';
import { CHAPTER_TWO } from './manuscript/chapter2.ts';
import { CHAPTER_THREE } from './manuscript/chapter3.ts';
import { CHAPTER_FOUR } from './manuscript/chapter4.ts';
import { CHAPTER_FIVE } from './manuscript/chapter5.ts';
import { CHAPTER_SIX } from './manuscript/chapter6.ts';

export const MANUSCRIPT_V1: BookVersionData = {
  metadata: {
    id: 'dating-wrong',
    version: 1,
    title: 'Dating Wrong',
    subtitle: 'Why We Choose the Wrong People and Repeat the Same Relationships',
    author: 'Gerishon Wanyeki',
    quote: 'Not every person we love is the person we should choose.',
    quoteAttribution: 'Gerishon Wanyeki',
    copyright: 'Copyright © 2026 by Gerishon Wanyeki. All rights reserved.',
    edition: 'First Edition, 2026',
    publisher: 'Mark & Alvis',
    isbn: '978-9914-29-399-9',
    printedIn: 'Printed in Kenya',
    price: {
      kes: 750,
      usd: 5.99,
    },
    active: true,
    storagePath: 'books/dating-wrong/v1',
    pageCount: 122,
    wordCount: 32292,
    estimatedReadingHours: 2.7,
    publishedAt: '2026-01-15',
    summary: 'A penetrating, compassionate, and spiritually discerning examination of modern relationship choices. Gerishon Wanyeki deconstructs the emotional myths, unhealed fractures, and cultural pressures that lead sincere believers and seekers into repetitive romantic despair—charting a clear path back to biblical clarity, personal sobriety, and covenant purpose.',
    themes: [
      'Discernment vs. Chemistry',
      'Breaking Repetitive Relationship Patterns',
      'Guarding the Heart & Emotional Sobriety',
      'The Cost of Moral & Spiritual Compromise',
      'Christian Courtship & Covenant Purpose',
    ],
  },
  sections: [
    ...FRONTMATTER_SECTIONS,
    CHAPTER_ONE,
    CHAPTER_TWO,
    CHAPTER_THREE,
    CHAPTER_FOUR,
    CHAPTER_FIVE,
    CHAPTER_SIX,
  ],
};
