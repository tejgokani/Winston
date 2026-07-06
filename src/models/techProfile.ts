import { z } from "zod";

export const TechnologyProfileSchema = z.object({
  frameworks: z.array(z.string()),
  languages: z.array(z.string()),
  databases: z.array(z.string()),
  authProviders: z.array(z.string()),
  paymentProviders: z.array(z.string()),
  cloud: z.array(z.string()),
  deployment: z.array(z.string()),
  detectedTags: z.array(z.string()),
});
export type TechnologyProfile = z.infer<typeof TechnologyProfileSchema>;
