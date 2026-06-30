const { z } = require('zod');

const passwordSchema = z.string().min(8, 'Password must be at least 8 characters').max(128);
const emailSchema = z.string().email('Invalid email').max(255).transform(function(v) { return v.toLowerCase().trim(); });
const emailOptional = emailSchema.optional().nullable().or(z.literal('').transform(function() { return undefined; }));

const authSchemas = {
  login: {
    body: z.object({
      email: emailSchema,
      password: z.string().min(1, 'Password is required'),
    }),
  },
  changePassword: {
    body: z.object({
      currentPassword: z.string().min(1, 'Current password is required'),
      newPassword: passwordSchema,
    }),
  },
  createUser: {
    body: z.object({
      name: z.string().min(1, 'Name is required').max(255).transform(function(v) { return v.trim(); }),
      email: emailSchema,
      password: passwordSchema,
      role: z.enum(['admin', 'manager', 'trainer', 'reception', 'member']).default('trainer'),
      trainer_id: z.string().optional().nullable(),
      member_id: z.string().optional().nullable(),
    }),
  },
};

const clientSchemas = {
  create: {
    body: z.object({
      name: z.string().min(1, 'Name is required').max(255).transform(function(v) { return v.trim(); }),
      mobile: z.string().max(20).optional().nullable(),
      email: emailOptional,
      gender: z.string().max(20).optional().nullable(),
      dob: z.string().optional().nullable(),
      address: z.string().max(500).optional().nullable(),
      trainer_id: z.string().optional().nullable(),
      package_type: z.string().optional().nullable(),
      base_amount: z.number().optional().nullable(),
      discount: z.number().optional().nullable(),
      final_amount: z.number().optional().nullable(),
      paid_amount: z.number().optional().nullable(),
      joining_date: z.string().optional().nullable(),
      pt_start_date: z.string().optional().nullable(),
      pt_end_date: z.string().optional().nullable(),
      payment_method: z.string().optional().nullable(),
      payment_date: z.string().optional().nullable(),
      weight: z.number().optional().nullable(),
      notes: z.string().max(1000).optional().nullable(),
      status: z.string().optional().nullable(),
      photo_url: z.string().optional().nullable(),
      biometric_code: z.string().optional().nullable(),
      plan_id: z.string().optional().nullable(),
    }),
  },
  update: {
    body: z.object({
      name: z.string().min(1).max(255).transform(function(v) { return v.trim(); }).optional(),
      mobile: z.string().max(20).optional().nullable(),
      email: emailOptional,
      gender: z.string().max(20).optional().nullable(),
      dob: z.string().optional().nullable(),
      address: z.string().max(500).optional().nullable(),
      trainer_id: z.string().optional().nullable(),
      package_type: z.string().optional().nullable(),
      base_amount: z.number().optional().nullable(),
      discount: z.number().optional().nullable(),
      final_amount: z.number().optional().nullable(),
      paid_amount: z.number().optional().nullable(),
      status: z.string().optional().nullable(),
      notes: z.string().max(1000).optional().nullable(),
      is_active: z.boolean().optional(),
    }),
  },
};

const paymentSchemas = {
  create: {
    body: z.object({
      client_id: z.string().min(1, 'client_id is required'),
      amount: z.number().positive('Amount must be positive'),
      method: z.string().max(50).optional(),
      date: z.string().optional(),
      payment_mode: z.string().max(50).optional(),
      notes: z.string().max(500).optional().nullable(),
      plan_id: z.string().optional().nullable(),
      trainer_id: z.string().optional().nullable(),
    }),
  },
};

const planSchemas = {
  create: {
    body: z.object({
      name: z.string().min(1).max(255).transform(function(v) { return v.trim(); }),
      kind: z.string().optional(),
      description: z.string().optional().nullable(),
      duration: z.string().optional(),
      base_amount: z.number().optional().nullable(),
      discount: z.number().optional().nullable(),
      final_amount: z.number().optional().nullable(),
      joining_fee: z.number().optional().nullable(),
      tax_pct: z.number().optional().nullable(),
      sessions_per_week: z.number().optional().nullable(),
      features: z.string().optional().nullable(),
      popular: z.boolean().optional(),
      color: z.string().optional(),
      is_active: z.boolean().optional(),
      status: z.string().optional(),
    }),
  },
  update: {
    body: z.object({
      name: z.string().min(1).max(255).transform(function(v) { return v.trim(); }).optional(),
      kind: z.string().optional(),
      description: z.string().optional().nullable(),
      duration: z.string().optional(),
      base_amount: z.number().optional().nullable(),
      discount: z.number().optional().nullable(),
      final_amount: z.number().optional().nullable(),
      joining_fee: z.number().optional().nullable(),
      tax_pct: z.number().optional().nullable(),
      sessions_per_week: z.number().optional().nullable(),
      features: z.string().optional().nullable(),
      popular: z.boolean().optional(),
      color: z.string().optional(),
      is_active: z.boolean().optional(),
      status: z.string().optional(),
    }),
  },
};

const staffSchemas = {
  create: {
    body: z.object({
      name: z.string().min(1).max(255).transform(function(v) { return v.trim(); }),
      email: emailOptional,
      phone: z.string().max(20).optional().nullable(),
      role: z.string().min(1, 'Role is required'),
      status: z.string().optional(),
    }),
  },
  update: {
    body: z.object({
      name: z.string().min(1).max(255).transform(function(v) { return v.trim(); }).optional(),
      email: emailOptional,
      phone: z.string().max(20).optional().nullable(),
      role: z.string().optional(),
      status: z.string().optional(),
    }),
  },
};

const renewSchema = {
  body: z.object({
    package_type: z.string().min(1, 'Package type is required'),
    pt_start_date: z.string().min(1, 'Start date is required'),
    pt_end_date: z.string().min(1, 'End date is required'),
    base_amount: z.number().optional().nullable(),
    discount: z.number().optional().nullable(),
    final_amount: z.number().optional().nullable(),
    paid_amount: z.number().optional().nullable(),
    payment_method: z.string().optional(),
    renewed_on: z.string().optional(),
    notes: z.string().max(1000).optional().nullable(),
  }),
};

const bulkAttendanceSchema = {
  body: z.object({
    records: z.array(z.object({
      ref_id: z.string().min(1, 'ref_id is required'),
      date: z.string().min(1, 'date is required'),
      status: z.enum(['present', 'absent', 'late', 'half_day']),
      type: z.string().optional(),
      ref_name: z.string().optional().nullable(),
      check_in: z.string().optional().nullable(),
      check_out: z.string().optional().nullable(),
      notes: z.string().max(500).optional().nullable(),
    })).min(1, 'At least one record is required').max(200, 'Maximum 200 records per bulk operation'),
  }),
};

const trainerSchemas = {
  create: {
    body: z.object({
      name: z.string().min(1).max(255).transform(function(v) { return v.trim(); }),
      mobile: z.string().max(20).optional().nullable(),
      email: emailOptional,
      dob: z.string().optional().nullable(),
      gender: z.string().max(20).optional().nullable(),
      address: z.string().max(500).optional().nullable(),
      role: z.string().optional(),
      joining_date: z.string().optional().nullable(),
      salary: z.number().optional().nullable(),
      incentive_rate: z.number().optional().nullable(),
      specialization: z.string().max(500).optional().nullable(),
      certifications: z.string().max(500).optional().nullable(),
      status: z.string().optional(),
      notes: z.string().max(1000).optional().nullable(),
      biometric_code: z.string().optional().nullable(),
    }),
  },
};

module.exports = {
  authSchemas,
  clientSchemas,
  paymentSchemas,
  planSchemas,
  staffSchemas,
  trainerSchemas,
  renewSchema,
  bulkAttendanceSchema,
  z,
};
